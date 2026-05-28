use anyhow::{ Context, Result };
use rcgen::{ CertificateParams, DistinguishedName, DnType, Issuer, KeyPair };
use std::{ fs::{ create_dir_all, write }, path::PathBuf };
use time::{ Duration, OffsetDateTime };
use uuid::Uuid;
use crate::backend;

pub fn run() -> Result<()> {
    let mut backend = backend::backend::Backend::new()?;

    // Self-signed PK

    let pk_pair = gen_key_pair()?;
    let mut esl = backend::esl_creator::EfiSigList::new(
        backend::guids::SignatureType::EfiCertX509Guid
    );
    let pk_cert = gen_x509_cert(&pk_pair[0], &pk_pair[1])?;
    esl.add_x509_certificate_to_esl(&pk_cert, Uuid::new_v4())?;
    let auth = gen_auth(&pk_pair[0], &pk_cert, &esl.to_bytes(), "PK")?;

    backend.storage_handler.write_to_file("pk", "key", &pk_pair[0])?;
    backend.storage_handler.write_to_file("pk", "pub", &pk_pair[1])?;    

    backend.var_writer.write_pk(&auth)?;

    // Self-signed KEK

    let kek_pair = gen_key_pair()?;
    let mut esl_kek = backend::esl_creator::EfiSigList::new(
        backend::guids::SignatureType::EfiCertX509Guid
    );
    let kek_cert = gen_x509_cert(&kek_pair[0], &kek_pair[1])?;
    esl_kek.add_x509_certificate_to_esl(&kek_cert, Uuid::new_v4())?;
    let auth = gen_auth(&pk_pair[0], &pk_cert, &esl_kek.to_bytes(), "KEK")?;

    backend.storage_handler.write_to_file("kek", "key", &kek_pair[0])?;
    backend.storage_handler.write_to_file("kek", "pub", &kek_pair[1])?;    

    backend.var_writer.write_kek(&auth)?;


    Ok(())
}

fn gen_key_pair() -> Result<[Vec<u8>; 2]> {
    let priv_key = backend::secret_creator::create_rsa_2048_private_key()?;
    let pub_key = backend::secret_creator::create_rsa_2048_public_key(&priv_key)?;
    Ok([priv_key, pub_key])
}

pub fn gen_x509_cert(signing_key: &[u8], pub_key: &[u8]) -> Result<Vec<u8>> {
    // Self-signed PK cert
    let issuer_key = KeyPair::from_pem(
        std::str::from_utf8(&signing_key).context("klucz prywatny nie jest poprawnym UTF-8 PEM")?
    )?;
    let issuer: Issuer<'_, KeyPair> = Issuer::new(CertificateParams::default(), issuer_key);
    let distinguished_name = backend::secret_creator::build_distinguished_name(
        "sbmgr generated certificate for PlatformKey",
        "PL",
        "sbmgr PK",
        "Secure Boot"
    );
    let now = OffsetDateTime::now_utc();
    let certificate_pem = backend::secret_creator::create_x509_certificate(
        &pub_key,
        issuer,
        distinguished_name,
        false,
        now,
        now + Duration::days(365)
    )?;
    Ok(certificate_pem)
}

pub fn gen_auth(
    priv_key: &[u8],
    cert_bytes: &[u8],
    esl_data: &[u8],
    var_name: &str
) -> Result<Vec<u8>> {
    Ok(backend::auth_creator::create_auth_data_data(&priv_key, &cert_bytes, &esl_data, var_name)?)
}
