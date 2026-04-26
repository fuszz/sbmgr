use directories::ProjectDirs;
use rcgen::{Issuer, CertificateParams, DistinguishedName, KeyPair, PKCS_RSA_SHA256};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, anyhow};
pub struct VarCreator {
    storage_dir: PathBuf,
}

impl VarCreator {
    pub fn new() -> Self {
        let proj_dirs = ProjectDirs::from("org", "SecureBootManager", "KeyStoreDirectory")
            .expect("Unable to access home directory");
        let storage_dir = proj_dirs.data_local_dir().to_path_buf();
        
        fs::create_dir_all(&storage_dir).expect("Unable to create directory");
        Self::apply_secure_permissions(&storage_dir);
        println!("Using key storage directory: {:?}", storage_dir.to_str());
        Self { storage_dir }
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let storage_dir = path.as_ref().to_path_buf();

        fs::create_dir_all(&storage_dir).expect("Unable to create directory");
        Self::apply_secure_permissions(&storage_dir);
        println!("Using key storage directory: {:?}", storage_dir.to_str());
        Self { storage_dir }
    }

        pub fn create_key_pair(&self, name: &str, file_prefix: &str) -> Result<()> {
            let mut params = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, name);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name = dn;

            let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
            let cert = params.self_signed(&key_pair)?;
            
            self.save_key_and_cert(file_prefix, &key_pair.serialize_pem(), &cert.pem())?;
            Ok(())
        }
        pub fn create_pk_file(&self, _name: &str, source_file: &str, dest_file: &str) -> Result<()> {
            let source_path = Path::new(source_file);
            let key_path = source_path.with_extension("key");

            if !key_path.exists() {
                return Err(anyhow!(
                    "missing PK private key for signing: {}",
                    key_path.display()
                ));
            }

            let temp_esl_path = Path::new(dest_file).with_extension("esl.tmp");

            let cert_to_esl = Command::new("cert-to-efi-sig-list")
                .arg(source_file)
                .arg(&temp_esl_path)
                .output()
                .map_err(|err| anyhow!("failed to run cert-to-efi-sig-list: {err}"))?;

            if !cert_to_esl.status.success() {
                let stderr = String::from_utf8_lossy(&cert_to_esl.stderr);
                return Err(anyhow!(
                    "cert-to-efi-sig-list failed for {}: {}",
                    source_file,
                    stderr.trim()
                ));
            }

            let sign_output = Command::new("sign-efi-sig-list")
                .args(["-c", source_file, "-k"])
                .arg(&key_path)
                .arg("PK")
                .arg(&temp_esl_path)
                .arg(dest_file)
                .output()
                .map_err(|err| anyhow!("failed to run sign-efi-sig-list: {err}"))?;

            let _ = fs::remove_file(&temp_esl_path);

            if !sign_output.status.success() {
                let stderr = String::from_utf8_lossy(&sign_output.stderr);
                return Err(anyhow!(
                    "sign-efi-sig-list failed for {}: {}",
                    dest_file,
                    stderr.trim()
                ));
            }

            println!("Created PK auth file: {} from source: {}", dest_file, source_file);
            Ok(())
        }

    pub fn create_kek(&self, name: &str, file_prefix: &str) -> Result<()> {
        let pk_key_pem = fs::read_to_string(self.storage_dir.join(file_prefix.to_owned() + ".key"))?;
        let pk_cert_pem = fs::read_to_string(self.storage_dir.join(file_prefix.to_owned() + ".crt"))?;
        
        let pk_keypair  = KeyPair::from_pem(&pk_key_pem)?;
        let pk_issuer = Issuer::from_ca_cert_pem(&pk_cert_pem, pk_keypair)?;

        let mut kek_params = CertificateParams::new(vec![name.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "SecureBoot KEK");
        kek_params.distinguished_name = dn;

        let kek_keypair = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
        
        let kek_cert = kek_params.signed_by(&kek_keypair, &pk_issuer)?;

        self.save_key_and_cert("KEK", &kek_keypair.serialize_pem(), &kek_cert.pem())?;
        Ok(())
    }

    pub fn sign_bootloader(&self, bootloader_path: &str) -> Result<Vec<u8>> {
        let mut file = File::open(bootloader_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let kek_key_pem = fs::read_to_string(self.storage_dir.join("KEK.key"))?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&kek_key_pem)?;
        let signing_key = SigningKey::<RsaSha256>::new(private_key);

        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&hash);
        Ok(signature.to_vec())
    }

    fn save_key_and_cert(&self, prefix: &str, key_pem: &str, cert_pem: &str) -> Result<()> {
        let key_path = self.storage_dir.join(format!("{}.key", prefix));
        let cert_path = self.storage_dir.join(format!("{}.crt", prefix));

        let mut key_file = File::create(&key_path)?;
        Self::apply_secure_file_permissions(&key_file);
        key_file.write_all(key_pem.as_bytes())?;

        let mut cert_file = File::create(&cert_path)?;
        cert_file.write_all(cert_pem.as_bytes())?;
        println!("Saved key and certificate files");
        Ok(())
    }

    #[cfg(unix)]
    fn apply_secure_permissions(path: &PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap_or(());
    }

    #[cfg(unix)]
    fn apply_secure_file_permissions(file: &File) {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).unwrap_or(());
    }

    #[cfg(windows)]
    fn apply_secure_permissions(_path: &PathBuf) {
        // Windows używa ACL domyślnie w %LOCALAPPDATA%
    }

    #[cfg(windows)]
    fn apply_secure_file_permissions(_file: &File) {
        // Zabezpieczenie dziedziczone z katalogu systemowego w Windows
    }
}