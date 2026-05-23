use uuid::Uuid;
use crate::backend::{storage_handler::StorageHandler, guids::*};
use anyhow::{Ok, Result, Error};
use std::io::Write;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct SignatureData {
    owner: Uuid,
    data: Vec<u8>,
}

impl SignatureData {
    pub fn new (owner: Uuid, data: Vec<u8>) -> Self {
        Self{owner, data}
    }
}

pub struct EfiSigList {
    signature_type: SignatureType,
    signature_list_size: u32,
    signature_header_size: u32, 
    signature_size: u32,     
    signature_header: Vec<u8>, 
    signatures: Vec<SignatureData>
}

impl EfiSigList {
    pub fn new(signature_type: SignatureType) -> Self {
        let size = match signature_type {
            SignatureType::EFI_CERT_SHA256_GUID => 48,
            SignatureType::EFI_CERT_RSA2048_GUID => 272,
            SignatureType::EFI_CERT_X509_GUID => 0,
            _ => 0,
        };
        Self {
            signature_type: signature_type,
            signature_list_size: 20,
            signature_header_size: 0,
            signature_size: size, 
            signature_header: vec![], 
            signatures: vec![],
        }
    }

    pub fn add_sha256_checksum_to_esl(&mut self, sha256checksum: &[u8], owner_guid: Uuid) -> Result<()> {
        if self.signature_type != SignatureType::EFI_CERT_SHA256_GUID {
            return Err(Error::msg("Improper signature type!"))
        }
        if sha256checksum.len() != 32 {
            return Err(Error::msg("not a valid SHA256 checksum"));
        }
        let entry = SignatureData::new(owner_guid, sha256checksum.to_vec());
        self.signatures.push(entry);
        self.signature_list_size += self.signature_size;
        Ok(())
    }

}

pub fn create_efi_sig_list_file(
    cert_file: &str,
    owner_guid: Uuid,
    esl_path: &str,
    sh: &StorageHandler
) -> Result<()> {
    let owner_guid_bytes = owner_guid.to_bytes_le();
    let cert_der = sh.read_from_file(cert_file, "der")?;

    let signature_size: u32 = 16 + (cert_der.len() as u32); // 16 bajtów na GUID właściciela + rozmiar certyfikatu
    let signature_list_size: u32 = 28 + signature_size; // 28 bajtów na nagłówek EFI_SIGNATURE_LIST + signature_size
    let signature_header_size: u32 = 0u32;

    // 4. Budowanie binarnego pliku ESL
    let mut esl_data = Vec::with_capacity(signature_list_size as usize);

    // -- Nagłówek EFI_SIGNATURE_LIST --
    esl_data.write_all(&EFI_CERT_X509_GUID.to_bytes_le())?;
    esl_data.write_all(&signature_list_size.to_le_bytes())?;
    esl_data.write_all(&signature_header_size.to_le_bytes())?;
    esl_data.write_all(&signature_size.to_le_bytes())?;

    // -- Dane EFI_SIGNATURE_DATA --
    esl_data.write_all(&owner_guid_bytes)?;
    esl_data.write_all(&cert_der)?;

    sh.write_to_file(esl_path, "esl", &esl_data)?;

    Ok(())
}
