use anyhow::{Result };
use rcgen::{ CertificateParams, DistinguishedName, KeyPair, PKCS_RSA_SHA256 };
use std::io::{Write};
use uuid::Uuid;
use crate::backend::storage_handler::StorageHandler;
use crate::backend::guids::*;

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
    esl_data.write_all(&EFI_CERT_X509_GUID.to_bytes_le())?;
    esl_data.write_all(&signature_list_size.to_le_bytes())?;
    esl_data.write_all(&signature_header_size.to_le_bytes())?;
    esl_data.write_all(&signature_size.to_le_bytes())?;

    // -- Dane EFI_SIGNATURE_DATA --
    esl_data.write_all(&owner_guid_bytes)?;
    esl_data.write_all(&cert_der)?;

    sh.write_to_file(esl_path, "esl", &esl_data)?;

    Ok(())
}

