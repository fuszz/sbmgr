use anyhow::{anyhow, ensure, Result};
use uuid::{Uuid, uuid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertType {
    X509,
    Sha256,
    Sha1,
    Sha224,
    Sha384,
    Sha512,
    Rsa2048,
    Rsa2048Sha1,
    Rsa2048Sha256,
    Pkcs7,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadRule {
    Fixed(usize),
    Variable,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CertSpec {
    pub guid: Uuid,
    pub cert_type: CertType,
    pub payload_rule: PayloadRule,
}

pub const CERT_SPECS: &[CertSpec] = &[
    // X.509 certificates
    CertSpec {
        guid: uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072"),
        cert_type: CertType::X509,
        payload_rule: PayloadRule::Variable,
    },
    // SHA hashes
    CertSpec {
        guid: uuid!("826ca512-cf10-4ac9-b187-be01496631bd"),
        cert_type: CertType::Sha1,
        payload_rule: PayloadRule::Fixed(20),
    },
    CertSpec {
        guid: uuid!("0b6e5233-a65c-44c9-9407-d9ab83bfc8bd"),
        cert_type: CertType::Sha224,
        payload_rule: PayloadRule::Fixed(28),
    },
    CertSpec {
        guid: uuid!("c1c41626-504c-4092-aca9-41f936934328"),
        cert_type: CertType::Sha256,
        payload_rule: PayloadRule::Fixed(32),
    },
    CertSpec {
        guid: uuid!("ff3e5307-9fd0-48c9-85f1-8ad56c701e01"),
        cert_type: CertType::Sha384,
        payload_rule: PayloadRule::Fixed(48),
    },
    CertSpec {
        guid: uuid!("093e0fae-a6c4-4f50-9f1b-d41e2b89c19a"),
        cert_type: CertType::Sha512,
        payload_rule: PayloadRule::Fixed(64),
    },
    // RSA keys and signatures
    CertSpec {
        guid: uuid!("3c5766e8-269c-4e34-aa14-ed776e85b3b6"),
        cert_type: CertType::Rsa2048,
        payload_rule: PayloadRule::Fixed(256),
    },
    CertSpec {
        guid: uuid!("67f8444f-8743-48f1-a328-1eaab8736080"),
        cert_type: CertType::Rsa2048Sha1,
        payload_rule: PayloadRule::Fixed(256),
    },
    CertSpec {
        guid: uuid!("e2b36190-879b-4a3d-ad8d-f2e7bba32784"),
        cert_type: CertType::Rsa2048Sha256,
        payload_rule: PayloadRule::Fixed(256),
    },
    // PKCS#7 signatures
    CertSpec {
        guid: uuid!("4aafd29d-68df-49ee-8aa9-347d375665a7"),
        cert_type: CertType::Pkcs7,
        payload_rule: PayloadRule::Variable,
    },
];

pub fn cert_spec_from_guid(guid: Uuid) -> CertSpec {
    CERT_SPECS
        .iter()
        .find(|s| s.guid == guid)
        .copied()
        .unwrap_or(CertSpec {
            guid,
            cert_type: CertType::Unknown,
            payload_rule: PayloadRule::Variable,
        })
}
