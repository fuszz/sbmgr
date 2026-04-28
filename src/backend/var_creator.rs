use anyhow::{Result, anyhow};
use directories::UserDirs;
use pkcs8::DecodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair, PKCS_RSA_SHA256};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{SignatureEncoding, Signer};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
pub struct VarCreator {
    storage_dir: PathBuf,
}

impl VarCreator {
    pub fn new() -> Self {
        let user_dirs = UserDirs::new()
            .expect("Unable to find current user's home directory");
        let proj_dirs = user_dirs.home_dir();
        let storage_dir = proj_dirs.to_path_buf();
        fs::create_dir_all(proj_dirs).expect("Unable to create directory");
        Self::apply_secure_permissions(&storage_dir);
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

    fn run_efi_command(&self, cmd_name: &str, mut cmd: Command) -> Result<()> {
        let output = cmd
            .output()
            .map_err(|err| anyhow!("failed to run {}: {err}", cmd_name))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("{} failed: {}", cmd_name, stderr.trim()));
        }
        Ok(())
    }

    pub fn sign_efi_var_file(&self, var_type: &str, source_file: &str, dest_file: &str) -> Result<()> {
        let source_path = Path::new(source_file);
        let key_path = source_path.with_extension("key");

        if !key_path.exists() {
            return Err(anyhow!(
                "missing private key for signing: {}",
                key_path.display()
            ));
        }

        let temp_esl_path = Path::new(dest_file).with_extension("esl.tmp");

        // Ensure temp file is always cleaned up, even on error
        let result = (|| -> Result<()> {
            self.run_efi_command(
                "cert-to-efi-sig-list",
                {
                    let mut cmd = Command::new("cert-to-efi-sig-list");
                    cmd.arg(source_file).arg(&temp_esl_path);
                    cmd
                },
            )?;

            self.run_efi_command(
                "sign-efi-sig-list",
                {
                    let mut cmd = Command::new("sign-efi-sig-list");
                    cmd.args(["-c", source_file, "-k"])
                        .arg(&key_path)
                        .arg(var_type)
                        .arg(&temp_esl_path)
                        .arg(dest_file);
                    cmd
                },
            )?;

            Ok(())
        })();

        let _ = fs::remove_file(&temp_esl_path);

        result?;
        println!(
            "Created {} auth file: {} from source: {}",
            var_type, dest_file, source_file
        );
        Ok(())
    }

    pub fn create_kek(&self, name: &str, file_prefix: &str) -> Result<()> {
        let pk_key_pem =
            fs::read_to_string(self.storage_dir.join(file_prefix.to_owned() + ".key"))?;
        let pk_cert_pem =
            fs::read_to_string(self.storage_dir.join(file_prefix.to_owned() + ".crt"))?;

        let pk_keypair = KeyPair::from_pem(&pk_key_pem)?;
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
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap_or(());
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
