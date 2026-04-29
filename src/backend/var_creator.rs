use anyhow::{ anyhow, Result };
use pkcs8::DecodePrivateKey;
use rcgen::{ CertificateParams, DistinguishedName, KeyPair, PKCS_RSA_SHA256 };
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{ SignatureEncoding, Signer };
use rsa::RsaPrivateKey;
use sha2::{ Digest, Sha256 };
use std::fs::{ self, File };
use std::io::{ Read, Write };
use std::path::{ Path, PathBuf };
use uuid::Uuid;
use openssl::{x509, pkey};
use crate::backend::storage_handler::StorageHandler;

pub fn create_key_pair(name: &str, file_prefix: &str, sh: &StorageHandler) -> Result<()> {
    let mut params: CertificateParams = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = dn;
    let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    sh.write_to_file(file_prefix, "key", key_pair.serialize_pem().as_bytes())?;
    sh.write_to_file(file_prefix, "crt", cert.pem().as_bytes())?;
    Ok(())
}

pub fn create_efi_sig_list_file(
    cert_file: &str,
    owner_guid: Uuid,
    esl_path: &str,
    sh: &StorageHandler
) -> Result<()> {
    let owner_guid_bytes = owner_guid.to_bytes_le();
    let cert_der = sh.read_from_file(cert_file, "der")?;

    let signature_size: u32 = 16 + (cert_der.len() as u32); // 16 bajtów na GUID właściciela + rozmiar certyfikatu
    let signature_list_size: u32 = 28 + signature_size; // 28 bajtów na nagłówek EFI_SIGNATURE_LIST + signature_size
    let signature_header_size: u32 = 0u32;

    // 4. Budowanie binarnego pliku ESL
    let mut esl_data = Vec::with_capacity(signature_list_size as usize);

    // -- Nagłówek EFI_SIGNATURE_LIST --
    esl_data.write_all(&EFI_CERT_X509_GUID)?;
    esl_data.write_all(&signature_list_size.to_le_bytes())?;
    esl_data.write_all(&signature_header_size.to_le_bytes())?;
    esl_data.write_all(&signature_size.to_le_bytes())?;

    // -- Dane EFI_SIGNATURE_DATA --
    esl_data.write_all(&owner_guid_bytes)?;
    esl_data.write_all(&cert_der)?;

    sh.write_to_file(esl_path, "esl", &esl_data)?;

    Ok(())
}



// fn signer_for_var( var_type: &str, source_file: &str) -> (PathBuf, PathBuf) {
//     if var_type.eq_ignore_ascii_case("KEK") {
//         return (sh.storage_dir.join("PK.crt"), sh.storage_dir.join("PK.key"));
//     }
//     if var_type.eq_ignore_ascii_case("db") || var_type.eq_ignore_ascii_case("dbx") {
//         return (sh.storage_dir.join("KEK.crt"), sh.storage_dir.join("KEK.key"));
//     }

//     let source_path = Path::new(source_file);
//     let signer_key = source_path.with_extension("key");
//     (PathBuf::from(source_file), signer_key)
// }

// fn resolve_source_cert_path( source_file: &str) -> PathBuf {
//     let input = PathBuf::from(source_file);
//     if input.exists() {
//         return input;
//     }

//     let in_storage = sh.storage_dir.join(source_file);
//     if in_storage.exists() {
//         return in_storage;
//     }

//     let input_no_ext = Path::new(source_file).extension().is_none();
//     if input_no_ext {
//         let with_ext = PathBuf::from(format!("{}.crt", source_file));
//         if with_ext.exists() {
//             return with_ext;
//         }

//         let in_storage_with_ext = sh.storage_dir.join(format!("{}.crt", source_file));
//         if in_storage_with_ext.exists() {
//             return in_storage_with_ext;
//         }

//         return in_storage_with_ext;
//     }

//     if input.is_absolute() {
//         input
//     } else {
//         in_storage
//     }
// }

// fn resolve_dest_auth_path( dest_file: &str) -> PathBuf {
//     let mut dest_path = if Path::new(dest_file).is_absolute() {
//         PathBuf::from(dest_file)
//     } else {
//         sh.storage_dir.join(dest_file)
//     };

//     if dest_path.extension().is_none() {
//         dest_path.set_extension("auth");
//     }

//     dest_path
// }

// fn sign_efi_var_file_with_signer(
//     
//     var_type: &str,
//     source_file: &str,
//     dest_file: &str,
//     signer_cert_file: &str,
//     signer_key_file: &str
// ) -> Result<()> {
//     let source_path = Path::new(source_file);
//     let signer_cert_path = Path::new(signer_cert_file);
//     let signer_key_path = Path::new(signer_key_file);

//     if !source_path.exists() {
//         return Err(anyhow!("missing source certificate: {}", source_path.display()));
//     }
//     if !signer_cert_path.exists() {
//         return Err(
//             anyhow!(
//                 "missing signer certificate for {}: {}",
//                 var_type,
//                 signer_cert_path.display()
//             )
//         );
//     }
//     if !signer_key_path.exists() {
//         return Err(
//             anyhow!(
//                 "missing signer private key for {}: {}",
//                 var_type,
//                 signer_key_path.display()
//             )
//         );
//     }

//     let temp_esl_path = Path::new(dest_file).with_extension("esl.tmp");

//     let result = (|| -> Result<()> {
//         sh.run_efi_command("cert-to-efi-sig-list", {
//             let mut cmd = Command::new("cert-to-efi-sig-list");
//             cmd.arg(source_file).arg(&temp_esl_path);
//             cmd
//         })?;

//         sh.run_efi_command("sign-efi-sig-list", {
//             let mut cmd = Command::new("sign-efi-sig-list");
//             cmd.args(["-c", signer_cert_file, "-k", signer_key_file])
//                 .arg(var_type)
//                 .arg(&temp_esl_path)
//                 .arg(dest_file);
//             cmd
//         })?;

//         Ok(())
//     })();

//     let _ = fs::remove_file(&temp_esl_path);

//     result?;
//     Ok(())
// }

// pub fn sign_efi_var_file(
//     
//     var_type: &str,
//     source_file: &str,
//     dest_file: &str
// ) -> Result<()> {
//     let resolved_source = sh.resolve_source_cert_path(source_file);
//     let resolved_dest = sh.resolve_dest_auth_path(dest_file);
//     let resolved_source_str = resolved_source.to_string_lossy().into_owned();
//     let resolved_dest_str = resolved_dest.to_string_lossy().into_owned();

//     let (signer_cert, signer_key) = sh.signer_for_var(var_type, &resolved_source_str);
//     sh.sign_efi_var_file_with_signer(
//         var_type,
//         &resolved_source_str,
//         &resolved_dest_str,
//         &signer_cert.to_string_lossy(),
//         &signer_key.to_string_lossy()
//     )
// }x

// pub fn sign_bootloader( bootloader_path: &str) -> Result<Vec<u8>> {
//     let mut file = File::open(bootloader_path)?;
//     let mut hasher = Sha256::new();
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     hasher.update(&buffer);
//     let hash = hasher.finalize();

//     let kek_key_pem = fs::read_to_string(sh.storage_dir.join("KEK.key"))?;
//     let private_key = RsaPrivateKey::from_pkcs8_pem(&kek_key_pem)?;
//     let signing_key = SigningKey::<RsaSha256>::new(private_key);

//     let signature: rsa::pkcs1v15::Signature = signing_key.sign(&hash);
//     Ok(signature.to_vec())
// }

// fn save_key_and_cert( prefix: &str, key_pem: &str, cert_pem: &str) -> Result<()> {
//     let key_path = sh.storage_dir.join(format!("{}.key", prefix));
//     let cert_path = sh.storage_dir.join(format!("{}.crt", prefix));

//     let mut key_file = File::create(&key_path)?;
//     Self::apply_secure_file_permissions(&key_file);
//     key_file.write_all(key_pem.as_bytes())?;

//     let mut cert_file = File::create(&cert_path)?;
//     cert_file.write_all(cert_pem.as_bytes())?;
//     Ok(())
// }
