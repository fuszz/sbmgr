use anyhow::{anyhow, Result};
use directories::UserDirs;
use pkcs8::DecodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_RSA_SHA256};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
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
        let user_dirs = UserDirs::new().expect("Unable to find current user's home directory");
        let proj_dirs = user_dirs.home_dir();
        let storage_dir = proj_dirs.to_path_buf();
        fs::create_dir_all(proj_dirs).expect("Unable to create directory");
        Self::apply_secure_permissions(&storage_dir);
        Self { storage_dir }
    }

    pub fn create_key_pair_files(&self, name: &str, file_prefix: &str) -> Result<()> {
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

    pub fn create_key_pair(&self, name: &str, file_prefix: &str) -> Result<()> {
        self.create_key_pair_files(name, file_prefix)
    }

    pub fn create_kek(&self, name: &str, signing_pk_prefix: &str) -> Result<()> {
        self.create_key_pair_files(name, "KEK")?;

        let source_file = self.storage_dir.join("KEK.crt");
        let dest_file = self.storage_dir.join("KEK.auth");
        let signer_cert = self.storage_dir.join(format!("{}.crt", signing_pk_prefix));
        let signer_key = self.storage_dir.join(format!("{}.key", signing_pk_prefix));

        self.sign_efi_var_file_with_signer(
            "KEK",
            &source_file.to_string_lossy(),
            &dest_file.to_string_lossy(),
            &signer_cert.to_string_lossy(),
            &signer_key.to_string_lossy(),
        )
    }

    pub fn sign_certificate_with_private_key(
        &self,
        certificate_file_path: &str,
        private_key_file_path: &str,
    ) -> Result<()> {
        let certificate_path = PathBuf::from(certificate_file_path);
        let private_key_path = PathBuf::from(private_key_file_path);
        if !certificate_path.exists() {
            return Err(anyhow!(
                "Invalid certificate file path: {}",
                certificate_path.display()
            ));
        }
        if !private_key_path.exists() {
            return Err(anyhow!(
                "Invalid private key file path: {}",
                private_key_path.display()
            ));
        }

        let certificate_bytes = fs::read(&certificate_path)?;
        let private_key_pem = fs::read_to_string(&private_key_path)?;

        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)?;
        let signing_key = SigningKey::<RsaSha256>::new(private_key);

        let mut hasher = Sha256::new();
        hasher.update(&certificate_bytes);
        let certificate_hash = hasher.finalize();

        let signature: rsa::pkcs1v15::Signature = signing_key.sign(&certificate_hash);
        let signature_path = PathBuf::from(format!("{}.sig", certificate_file_path));
        fs::write(&signature_path, signature.to_vec())?;

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

    fn signer_for_var(&self, var_type: &str, source_file: &str) -> (PathBuf, PathBuf) {
        if var_type.eq_ignore_ascii_case("KEK") {
            return (self.storage_dir.join("PK.crt"), self.storage_dir.join("PK.key"));
        }
        if var_type.eq_ignore_ascii_case("db") || var_type.eq_ignore_ascii_case("dbx") {
            return (self.storage_dir.join("KEK.crt"), self.storage_dir.join("KEK.key"));
        }

        let source_path = Path::new(source_file);
        let signer_key = source_path.with_extension("key");
        (PathBuf::from(source_file), signer_key)
    }

    fn resolve_source_cert_path(&self, source_file: &str) -> PathBuf {
        let input = PathBuf::from(source_file);
        if input.exists() {
            return input;
        }

        let in_storage = self.storage_dir.join(source_file);
        if in_storage.exists() {
            return in_storage;
        }

        let input_no_ext = Path::new(source_file).extension().is_none();
        if input_no_ext {
            let with_ext = PathBuf::from(format!("{}.crt", source_file));
            if with_ext.exists() {
                return with_ext;
            }

            let in_storage_with_ext = self.storage_dir.join(format!("{}.crt", source_file));
            if in_storage_with_ext.exists() {
                return in_storage_with_ext;
            }

            return in_storage_with_ext;
        }

        if input.is_absolute() {
            input
        } else {
            in_storage
        }
    }

    fn resolve_dest_auth_path(&self, dest_file: &str) -> PathBuf {
        let mut dest_path = if Path::new(dest_file).is_absolute() {
            PathBuf::from(dest_file)
        } else {
            self.storage_dir.join(dest_file)
        };

        if dest_path.extension().is_none() {
            dest_path.set_extension("auth");
        }

        dest_path
    }

    fn sign_efi_var_file_with_signer(
        &self,
        var_type: &str,
        source_file: &str,
        dest_file: &str,
        signer_cert_file: &str,
        signer_key_file: &str,
    ) -> Result<()> {
        let source_path = Path::new(source_file);
        let signer_cert_path = Path::new(signer_cert_file);
        let signer_key_path = Path::new(signer_key_file);

        if !source_path.exists() {
            return Err(anyhow!("missing source certificate: {}", source_path.display()));
        }
        if !signer_cert_path.exists() {
            return Err(anyhow!(
                "missing signer certificate for {}: {}",
                var_type,
                signer_cert_path.display()
            ));
        }
        if !signer_key_path.exists() {
            return Err(anyhow!(
                "missing signer private key for {}: {}",
                var_type,
                signer_key_path.display()
            ));
        }

        let temp_esl_path = Path::new(dest_file).with_extension("esl.tmp");

        let result = (|| -> Result<()> {
            self.run_efi_command("cert-to-efi-sig-list", {
                let mut cmd = Command::new("cert-to-efi-sig-list");
                cmd.arg(source_file).arg(&temp_esl_path);
                cmd
            })?;

            self.run_efi_command("sign-efi-sig-list", {
                let mut cmd = Command::new("sign-efi-sig-list");
                cmd.args(["-c", signer_cert_file, "-k", signer_key_file])
                    .arg(var_type)
                    .arg(&temp_esl_path)
                    .arg(dest_file);
                cmd
            })?;

            Ok(())
        })();

        let _ = fs::remove_file(&temp_esl_path);

        result?;
        Ok(())
    }

    pub fn sign_efi_var_file(&self, var_type: &str, source_file: &str, dest_file: &str) -> Result<()> {
        let resolved_source = self.resolve_source_cert_path(source_file);
        let resolved_dest = self.resolve_dest_auth_path(dest_file);
        let resolved_source_str = resolved_source.to_string_lossy().into_owned();
        let resolved_dest_str = resolved_dest.to_string_lossy().into_owned();

        let (signer_cert, signer_key) = self.signer_for_var(var_type, &resolved_source_str);
        self.sign_efi_var_file_with_signer(
            var_type,
            &resolved_source_str,
            &resolved_dest_str,
            &signer_cert.to_string_lossy(),
            &signer_key.to_string_lossy(),
        )
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
        // Windows uses inherited ACLs in %LOCALAPPDATA%.
    }

    #[cfg(windows)]
    fn apply_secure_file_permissions(_file: &File) {
        // Security is inherited from the system directory on Windows.
    }
}
