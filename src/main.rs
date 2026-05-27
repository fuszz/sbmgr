use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use std::{fs::{create_dir_all, write}, path::PathBuf};
use time::{Duration, OffsetDateTime};

mod backend;
mod tui;

fn main() -> Result<()> {
    let artifacts = build_secure_boot_artifacts()?;

    println!("Wygenerowano pliki:");
    println!("  {}", artifacts.private_key.display());
    println!("  {}", artifacts.public_key.display());
    println!("  {}", artifacts.certificate.display());
    println!("  {}", artifacts.esl.display());
    println!("  {}", artifacts.auth.display());

    Ok(())
}

struct SecureBootArtifacts {
    private_key: PathBuf,
    public_key: PathBuf,
    certificate: PathBuf,
    esl: PathBuf,
    auth: PathBuf,
}

fn build_secure_boot_artifacts() -> Result<SecureBootArtifacts> {
    let output_dir = PathBuf::from("secure_boot_artifacts");
    create_dir_all(&output_dir)
        .with_context(|| format!("nie można utworzyć katalogu {}", output_dir.display()))?;

    let private_key_pem = backend::secret_creator::create_rsa_2048_private_key()?;
    let public_key_pem = backend::secret_creator::create_rsa_2048_public_key(private_key_pem.clone())?;

    let issuer_key = KeyPair::from_pem(
        std::str::from_utf8(&private_key_pem)
            .context("klucz prywatny nie jest poprawnym UTF-8 PEM")?,
    )?;
    let issuer = Issuer::new(CertificateParams::default(), issuer_key);
    let distinguished_name = build_distinguished_name(
        "sbmgr generated certificate",
        "PL",
        "sbmgr",
        "Secure Boot",
    );

    let now = OffsetDateTime::now_utc();
    let certificate_pem = backend::secret_creator::create_x509_certificate(
        &public_key_pem,
        issuer,
        distinguished_name,
        false,
        now,
        now + Duration::days(365),
    )?;

    let mut esl = backend::esl_creator::EfiSigList::new(backend::guids::SignatureType::EfiCertX509Guid);
    esl.add_x509_certificate_to_esl(&certificate_pem, uuid::Uuid::new_v4())?;
    let esl_bytes = esl.to_bytes();

    let auth_bytes = backend::auth_creator::create_auth_data_data(
        &private_key_pem,
        &certificate_pem,
        &esl_bytes,
        "PK",
    )?;

    let private_key_path = output_dir.join("pk-private.pem");
    let public_key_path = output_dir.join("pk-public.pem");
    let certificate_path = output_dir.join("pk-cert.pem");
    let esl_path = output_dir.join("pk.esl");
    let auth_path = output_dir.join("pk.auth");

    write(&private_key_path, &private_key_pem)?;
    write(&public_key_path, &public_key_pem)?;
    write(&certificate_path, &certificate_pem)?;
    write(&esl_path, &esl_bytes)?;
    write(&auth_path, &auth_bytes)?;

    Ok(SecureBootArtifacts {
        private_key: private_key_path,
        public_key: public_key_path,
        certificate: certificate_path,
        esl: esl_path,
        auth: auth_path,
    })
}

fn build_distinguished_name(
    common_name: &str,
    country_name: &str,
    organization_name: &str,
    organizational_unit_name: &str,
) -> DistinguishedName {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, country_name);
    distinguished_name.push(DnType::OrganizationName, organization_name);
    distinguished_name.push(DnType::OrganizationalUnitName, organizational_unit_name);
    distinguished_name.push(DnType::CommonName, common_name);
    distinguished_name
}



