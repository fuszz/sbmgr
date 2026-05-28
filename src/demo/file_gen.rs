use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use std::{fs::{create_dir_all, write}, path::PathBuf};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::backend;

pub fn run() -> Result<()> {
    let artifacts = build_secure_boot_artifacts()?;

    println!("Wygenerowano pliki:");
    println!("  {}", artifacts.private_key.display());
    println!("  {}", artifacts.public_key.display());
    println!("  {}", artifacts.certificate.display());
    println!("  {}", artifacts.esl.display());
    println!("  {}", artifacts.auth.display());
    if !artifacts.others.is_empty() {
        println!("Dodatkowo wygenerowano pliki:");
        for p in &artifacts.others {
            println!("  {}", p.display());
        }
    }

    Ok(())
}

struct SecureBootArtifacts {
    private_key: PathBuf,
    public_key: PathBuf,
    certificate: PathBuf,
    esl: PathBuf,
    auth: PathBuf,
    others: Vec<PathBuf>,
}

fn build_secure_boot_artifacts() -> Result<SecureBootArtifacts> {
    let output_dir = PathBuf::from("secure_boot_artifacts");
    create_dir_all(&output_dir)
        .with_context(|| format!("nie można utworzyć katalogu {}", output_dir.display()))?;

    let private_key_pem = backend::secret_creator::create_rsa_2048_private_key()?;
    let public_key_pem = backend::secret_creator::create_rsa_2048_public_key(&private_key_pem)?;

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
    esl.add_x509_certificate_to_esl(&certificate_pem, Uuid::new_v4())?;
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

    let kek_private_key_pem = backend::secret_creator::create_rsa_2048_private_key()?;
    let kek_public_key_pem = backend::secret_creator::create_rsa_2048_public_key(&kek_private_key_pem)?;

    let kek_issuer_key = KeyPair::from_pem(
        std::str::from_utf8(&kek_private_key_pem)
            .context("kek private key is not valid UTF-8 PEM")?,
    )?;
    let kek_issuer = Issuer::new(CertificateParams::default(), kek_issuer_key);
    let kek_dn = build_distinguished_name("sbmgr KEK certificate", "PL", "sbmgr", "Secure Boot");
    let kek_certificate_pem = backend::secret_creator::create_x509_certificate(
        &kek_public_key_pem,
        kek_issuer,
        kek_dn,
        false,
        now,
        now + Duration::days(365),
    )?;

    let mut kek_esl = backend::esl_creator::EfiSigList::new(backend::guids::SignatureType::EfiCertX509Guid);
    kek_esl.add_x509_certificate_to_esl(&kek_certificate_pem, Uuid::new_v4())?;
    let kek_esl_bytes = kek_esl.to_bytes();

    let kek_auth_bytes = backend::auth_creator::create_auth_data_data(
        &kek_private_key_pem,
        &kek_certificate_pem,
        &kek_esl_bytes,
        "KEK",
    )?;

    let kek_private_path = output_dir.join("kek-private.pem");
    let kek_public_path = output_dir.join("kek-public.pem");
    let kek_certificate_path = output_dir.join("kek-cert.pem");
    let kek_esl_path = output_dir.join("kek.esl");
    let kek_auth_path = output_dir.join("kek.auth");

    write(&kek_private_path, &kek_private_key_pem)?;
    write(&kek_public_path, &kek_public_key_pem)?;
    write(&kek_certificate_path, &kek_certificate_pem)?;
    write(&kek_esl_path, &kek_esl_bytes)?;
    write(&kek_auth_path, &kek_auth_bytes)?;

    let db_private_key_pem = backend::secret_creator::create_rsa_2048_private_key()?;
    let db_public_key_pem = backend::secret_creator::create_rsa_2048_public_key(&db_private_key_pem)?;

    let kek_issuer_for_sign: KeyPair = KeyPair::from_pem(
        std::str::from_utf8(&kek_private_key_pem)
            .context("kek private key is not valid UTF-8 PEM for signing")?,
    )?;
    let kek_issuer_for_db = Issuer::new(CertificateParams::default(), kek_issuer_for_sign);
    let db_dn = build_distinguished_name("sbmgr DB certificate", "PL", "sbmgr", "Secure Boot");
    let db_certificate_pem = backend::secret_creator::create_x509_certificate(
        &db_public_key_pem,
        kek_issuer_for_db,
        db_dn,
        false,
        now,
        now + Duration::days(365),
    )?;

    let mut db_esl = backend::esl_creator::EfiSigList::new(backend::guids::SignatureType::EfiCertX509Guid);
    db_esl.add_x509_certificate_to_esl(&db_certificate_pem, Uuid::new_v4())?;
    let db_esl_bytes = db_esl.to_bytes();

    let db_auth_bytes: Vec<u8> = backend::auth_creator::create_auth_data_data(
        &kek_private_key_pem,
        &kek_certificate_pem,
        &db_esl_bytes,
        "db",
    )?;

    let db_private_path = output_dir.join("db-private.pem");
    let db_public_path = output_dir.join("db-public.pem");
    let db_certificate_path = output_dir.join("db-cert.pem");
    let db_esl_path = output_dir.join("db.esl");
    let db_auth_path = output_dir.join("db.auth");

    write(&db_private_path, &db_private_key_pem)?;
    write(&db_public_path, &db_public_key_pem)?;
    write(&db_certificate_path, &db_certificate_pem)?;
    write(&db_esl_path, &db_esl_bytes)?;
    write(&db_auth_path, &db_auth_bytes)?;

    let mut dbx_esl = backend::esl_creator::EfiSigList::new(backend::guids::SignatureType::EfiCertSha256Guid);
    dbx_esl.add_sha256_checksum_to_esl(&hex::decode("d2f283610bac9f60ac34bbf4dc73b59a9536e36d11eef9c19a555866fb740220").expect("Parsing error"), Uuid::new_v4())?;
    dbx_esl.add_sha256_checksum_to_esl(&hex::decode("f2f283610bac9f60ac34bbf4dc73b59a9536e36d11eef9c19a555866fb740220").expect("Parsing error"), Uuid::new_v4())?;
    dbx_esl.add_sha256_checksum_to_esl(&hex::decode("a2f283610bac9f60ac34bbf4dc73b59a9536e36d11eef9c19a555866fb740220").expect("Parsing error"), Uuid::new_v4())?;
    dbx_esl.add_sha256_checksum_to_esl(&hex::decode("e2f283610bac9f60ac34bbf4dc73b59a9536e36d11eef9c19a555866fb740220").expect("Parsing error"), Uuid::new_v4())?;

    let dbx_esl_bytes = dbx_esl.to_bytes();
    println!("{:?}", dbx_esl);
    let dbx_auth_bytes = backend::auth_creator::create_auth_data_data(
        &kek_private_key_pem,
        &kek_certificate_pem,
        &dbx_esl_bytes,
        "dbx",
    )?;

    let dbx_esl_path = output_dir.join("dbx.esl");
    let dbx_auth_path = output_dir.join("dbx.auth");
    write(&dbx_esl_path, &dbx_esl_bytes)?;
    write(&dbx_auth_path, &dbx_auth_bytes)?;

    Ok(SecureBootArtifacts {
        private_key: private_key_path,
        public_key: public_key_path,
        certificate: certificate_path,
        esl: esl_path,
        auth: auth_path,
        others: vec![
            kek_private_path,
            kek_public_path,
            kek_certificate_path,
            kek_esl_path,
            kek_auth_path,
            db_private_path,
            db_public_path,
            db_certificate_path,
            db_esl_path,
            db_auth_path,
            dbx_esl_path,
            dbx_auth_path,
        ],
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