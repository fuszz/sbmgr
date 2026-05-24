use anyhow::Result;
use openssl::{ pkey::PKey, rsa::Rsa };
use rcgen::{
    BasicConstraints,
    CertificateParams,
    DistinguishedName,
    DnType,
    IsCa,
    SubjectPublicKeyInfo,
    Issuer,
    KeyPair,
    CertifiedKey,
};
use time::OffsetDateTime;
use sha2::{Digest, Sha256};

pub fn create_rsa_2048_private_key() -> Result<Vec<u8>> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;
    let private_key_pem = key_pair.private_key_to_pem_pkcs8()?;
    Ok(private_key_pem)
}

pub fn create_rsa_2048_public_key(private_key_pem: Vec<u8>) -> Result<Vec<u8>> {
    let key_pair = PKey::private_key_from_pem(&private_key_pem)?;
    let public_key = key_pair.public_key_to_pem()?;
    Ok(public_key)
}

fn build_distinguished_name(
    common_name: &str,
    country_name: &str,
    organization_name: &str,
    organizational_unit_name: &str
) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, country_name);
    dn.push(DnType::OrganizationName, organization_name);
    dn.push(DnType::OrganizationalUnitName, organizational_unit_name);
    dn.push(DnType::CommonName, common_name);
    dn
}

pub fn create_sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}


pub fn create_x509_certificate(
    public_key: &[u8],
    issuer: Issuer<KeyPair>,
    distinguished_name: DistinguishedName,
    is_ca: bool,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<(Vec<u8>)> {
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = if is_ca { IsCa::Ca(BasicConstraints::Unconstrained) } else { IsCa::NoCa };
    params.not_before = not_before;
    params.not_after = not_after;
    let subject_public_key_info = SubjectPublicKeyInfo::from_pem(std::str::from_utf8(&public_key)?)?;
    let cert = params.signed_by(&subject_public_key_info, &issuer)?;
    Ok(cert.pem().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{pkey::PKey, rsa::Rsa, x509::X509};
    use std::time::{Duration, SystemTime};

    #[test]
    fn create_x509_certificate_embeds_subject_and_public_key() -> Result<()> {
        let key_pair = KeyPair::generate()?;
        let public_key_pem = key_pair.public_key_pem();
        let issuer = Issuer::new(CertificateParams::default(), key_pair);
        let distinguished_name = build_distinguished_name(
            "sbmgr test cert",
            "PL",
            "sbmgr",
            "Secure Boot",
        );
        let cert_pem = create_x509_certificate(
            &public_key_pem.as_bytes(),
            issuer,
            distinguished_name,
            true,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + Duration::from_secs(60 * 60 * 24),
        )?;

        let cert = X509::from_pem(&cert_pem).expect("x509 parsing");

        let subject_cn = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .expect("subject cn")
            .data()
            .as_utf8()
            .expect("utf8 subject cn");
        assert_eq!(subject_cn.to_string(), "sbmgr test cert");

        let cert_public_key_pem = cert
            .public_key()
            .expect("certificate public key")
            .public_key_to_pem()?;

        let cert_public_key_pem_str: String = String::from_utf8(cert_public_key_pem)
            .expect("public key pem utf8");

        assert_eq!(cert_public_key_pem_str, public_key_pem);
        Ok(())
    }

    #[test]
    fn sha256_digest_matches_known_vector() {
        let digest = create_sha256_digest(b"abc");
        assert_eq!(hex::encode(digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn create_rsa_2048_private_key_returns_valid_pkcs8_pem() {
        let private_key_pem = create_rsa_2048_private_key().expect("private key generation");

        let private_key = PKey::private_key_from_pem(&private_key_pem)
            .expect("pkcs8 pem parsing");
        let public_key_pem = private_key.public_key_to_pem().expect("public key pem");

        assert!(private_key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert!(!public_key_pem.is_empty());
    }

    #[test]
    fn create_rsa_2048_public_key_derives_public_key_from_private_key() {
        let rsa = Rsa::generate(2048).expect("rsa generation");
        let key_pair = PKey::from_rsa(rsa).expect("pkey conversion");

        let private_key_pem = key_pair
            .private_key_to_pem_pkcs8()
            .expect("private key pem");
        let expected_public_key_pem = key_pair.public_key_to_pem().expect("public key pem");

        let public_key_pem = create_rsa_2048_public_key(private_key_pem)
            .expect("public key derivation");

        assert_eq!(public_key_pem, expected_public_key_pem);
    }
}
