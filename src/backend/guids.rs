use uuid::{uuid, Uuid};

pub const EFI_CERT_X509_GUID: Uuid = uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");
pub const EFI_CERT_SHA256_GUID: Uuid = uuid!("c1c41626-504c-4092-aca9-41f936934328");
pub const EFI_CERT_RSA2048_GUID: Uuid = uuid!("3c5766e8-269c-4e34-aa14-ed776e85b3b6");
pub const EFI_CERT_TYPE_PKCS7_GUID: Uuid = uuid!("4aafd29d-68df-49ee-8aa9-347d375665a7");
pub const EFI_GLOBAL_VARIABLE_GUID: Uuid = uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: Uuid = uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
pub const EFI_PK_VARIABLE_ATTRIBUTES: u32 = 0x00000027;

#[derive(PartialEq, Debug)]
pub enum SignatureType{
    EfiCertSha256Guid,
    EfiCertRsa2048Guid,
    EfiCertX509Guid,
}

impl SignatureType {
pub fn to_bytes_le(&self) -> [u8; 16] {
        match self {
            SignatureType::EfiCertSha256Guid  => EFI_CERT_SHA256_GUID.to_bytes_le(),
            SignatureType::EfiCertRsa2048Guid => EFI_CERT_RSA2048_GUID.to_bytes_le(),
            SignatureType::EfiCertX509Guid    => EFI_CERT_X509_GUID.to_bytes_le(),
        }
    }
}