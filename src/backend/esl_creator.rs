use uuid::Uuid;
use x509_parser::nom::AsBytes;
use crate::backend::guids::*;
use anyhow::{ Ok, Result, Error };
use std::io::Write;
use pem::parse;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct SignatureData {
    owner: Uuid,
    data: Vec<u8>,
}

impl SignatureData {
    pub fn new(owner: Uuid, data: Vec<u8>) -> Self {
        Self { owner, data }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buff: Vec<u8> = vec![];
        buff.extend_from_slice(self.owner.as_bytes());
        buff.extend_from_slice(self.data.as_bytes());
        buff
    }
}

pub struct EfiSigList {
    signature_type: SignatureType,
    signature_list_size: u32,
    signature_header_size: u32,
    signature_size: u32,
    signature_header: Vec<u8>,
    signatures: Vec<SignatureData>,
}

impl EfiSigList {
    pub fn new(signature_type: SignatureType) -> Self {
        let size = match signature_type {
            SignatureType::EfiCertSha256Guid => 48,
            SignatureType::EfiCertRsa2048Guid => 272,
            SignatureType::EfiCertX509Guid => 0,
        };
        Self {
            signature_type: signature_type,
            signature_list_size: 28,
            signature_header_size: 0,
            signature_size: size,
            signature_header: vec![],
            signatures: vec![],
        }
    }

    pub fn add_sha256_checksum_to_esl(
        &mut self,
        sha256checksum: &[u8],
        owner_guid: Uuid
    ) -> Result<()> {
        if self.signature_type != SignatureType::EfiCertSha256Guid {
            return Err(Error::msg("Improper signature type!"));
        }
        if sha256checksum.len() != 32 {
            return Err(Error::msg("not a valid SHA256 checksum"));
        }
        let entry = SignatureData::new(owner_guid, sha256checksum.to_vec());
        self.signatures.push(entry);
        self.signature_list_size += self.signature_size;
        Ok(())
    }

    pub fn add_rsa2048_public_key_to_esl(
        &mut self,
        rsa2048_public_key_pem: &[u8],
        owner_guid: Uuid
    ) -> Result<()> {
        if self.signature_type != SignatureType::EfiCertRsa2048Guid {
            return Err(Error::msg("Improper signature type!"));
        }
        let der = parse(rsa2048_public_key_pem)?.contents().to_vec();
        let entry = SignatureData::new(owner_guid, der);
        self.signatures.push(entry);
        self.signature_list_size += self.signature_size;
        Ok(())
    }

    pub fn add_x509_certificate_to_esl(
        &mut self,
        x509_certificate_pem: &[u8],
        owner_guid: Uuid
    ) -> Result<()> {
        if self.signature_type != SignatureType::EfiCertX509Guid {
            return Err(Error::msg("Improper signature type!"));
        }
        if self.signature_size > 0 {
            return Err(
                Error::msg("EFI Signature List should not contains more than 1 X509 Certificate")
            );
        }
        let x509_der = match parse(x509_certificate_pem) {
            std::result::Result::Ok(p) => {
                if p.tag() != "CERTIFICATE" {
                    return Err(Error::msg("PEM is not a valid certificate"));
                }
                p.contents().to_vec()
            }
            std::result::Result::Err(_) => {
                return Err(Error::msg("Invalid PEM format"));
            }
        };

        let entry = SignatureData::new(owner_guid, x509_der);
        let entry_size = 16 + entry.data.len();
        self.signatures.push(entry);
        self.signature_size = entry_size as u32;
        self.signature_list_size += entry_size as u32;

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.signature_type.to_bytes_le());
        buffer.extend_from_slice(&self.signature_list_size.to_le_bytes());
        buffer.extend_from_slice(&self.signature_header_size.to_le_bytes());
        buffer.extend_from_slice(&self.signature_size.to_le_bytes());

        for sig in &self.signatures {
            buffer.extend_from_slice(&sig.to_bytes());
        }

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::var_parser::parse_signature_list;
    use openssl::{pkey::PKey, rsa::Rsa};
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_RSA_SHA256};

    fn generate_test_cert_pem() -> Vec<u8> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "sbmgr.test");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).expect("key generation");
        let cert = params.self_signed(&key_pair).expect("certificate generation");
        cert.pem().into_bytes()
    }

    fn generate_test_rsa_public_key_pem() -> Vec<u8> {
        let rsa = Rsa::generate(2048).expect("rsa generation");
        let key_pair = PKey::from_rsa(rsa).expect("pkey conversion");
        key_pair.public_key_to_pem().expect("public key pem")
    }

    #[test]
    fn creates_sha256_esl_entry() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertSha256Guid);
        let checksum = [0xAA; 32];
        let owner = Uuid::new_v4();

        esl.add_sha256_checksum_to_esl(&checksum, owner)
            .expect("sha256 entry creation");

        assert_eq!(esl.signature_list_size, 68);
        assert_eq!(esl.signatures.len(), 1);
        assert_eq!(esl.signatures[0].owner, owner);
        assert_eq!(esl.signatures[0].data, checksum);
    }

    #[test]
    fn rejects_sha256_entry_for_wrong_signature_type() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertRsa2048Guid);
        let checksum = [0xAA; 32];

        let error = esl
            .add_sha256_checksum_to_esl(&checksum, Uuid::new_v4())
            .expect_err("expected signature type validation error");

        assert_eq!(error.to_string(), "Improper signature type!");
    }

    #[test]
    fn rejects_sha256_entry_with_invalid_length() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertSha256Guid);
        let checksum = [0xAA; 31];

        let error = esl
            .add_sha256_checksum_to_esl(&checksum, Uuid::new_v4())
            .expect_err("expected checksum length validation error");

        assert_eq!(error.to_string(), "not a valid SHA256 checksum");
    }

    #[test]
    fn creates_rsa2048_esl_entry() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertRsa2048Guid);
        let public_key_pem = generate_test_rsa_public_key_pem();
        let public_key_der = parse(&public_key_pem).expect("public key pem parsing").contents().to_vec();
        let owner = Uuid::new_v4();

        esl.add_rsa2048_public_key_to_esl(&public_key_pem, owner)
            .expect("rsa entry creation");

        assert_eq!(esl.signature_list_size, 292);
        assert_eq!(esl.signatures.len(), 1);
        assert_eq!(esl.signatures[0].owner, owner);
        assert_eq!(esl.signatures[0].data, public_key_der);
    }

    #[test]
    fn creates_x509_esl_entry() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertX509Guid);
        let certificate_pem = generate_test_cert_pem();
        let certificate_der = parse(&certificate_pem).expect("certificate pem parsing").contents().to_vec();
        let owner = Uuid::new_v4();

        esl.add_x509_certificate_to_esl(&certificate_pem, owner)
            .expect("x509 entry creation");

        assert_eq!(esl.signature_size, (16 + certificate_der.len()) as u32);
        assert_eq!(esl.signature_list_size, (20 + 16 + certificate_der.len()) as u32);
        assert_eq!(esl.signatures.len(), 1);
        assert_eq!(esl.signatures[0].owner, owner);
        assert_eq!(esl.signatures[0].data, certificate_der);
    }

    #[test]
    fn rejects_second_x509_entry() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertX509Guid);
        let certificate_pem = generate_test_cert_pem();

        esl.add_x509_certificate_to_esl(&certificate_pem, Uuid::new_v4())
            .expect("first x509 entry creation");

        let error = esl
            .add_x509_certificate_to_esl(&certificate_pem, Uuid::new_v4())
            .expect_err("expected single-certificate validation error");

        assert_eq!(
            error.to_string(),
            "EFI Signature List should not contains more than 1 X509 Certificate"
        );
    }

    #[test]
    fn rejects_x509_entry_for_wrong_signature_type() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertSha256Guid);
        let certificate_pem = generate_test_cert_pem();

        let error = esl
            .add_x509_certificate_to_esl(&certificate_pem, Uuid::new_v4())
            .expect_err("expected signature type validation error");

        assert_eq!(error.to_string(), "Improper signature type!");
    }

    #[test]
    fn rejects_invalid_x509_pem() {
        let mut esl = EfiSigList::new(SignatureType::EfiCertX509Guid);
        let invalid_pem = b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";

        let error = esl
            .add_x509_certificate_to_esl(invalid_pem, Uuid::new_v4())
            .expect_err("expected invalid PEM error");

        assert_eq!(error.to_string(), "PEM is not a valid certificate");
    }

}
