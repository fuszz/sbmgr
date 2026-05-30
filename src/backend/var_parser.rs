use anyhow::{ anyhow, Context, Result };
use hex::encode;
use uuid::Uuid;
use x509_parser::prelude::*;
use crate::backend::guids::*;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignatureData {
    pub owner: Uuid,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureList {
    pub signature_type: Uuid,
    pub signature_header: Vec<u8>,
    pub signatures: Vec<SignatureData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureBootVariable {
    pub signature_lists: Vec<SignatureList>,
}

pub fn parse_secure_boot_variable(data: &[u8]) -> Result<SecureBootVariable> {
    Ok(SecureBootVariable {
        signature_lists: parse_signature_lists(data)?,
    })
}

pub fn parse_signature_lists(data: &[u8]) -> Result<Vec<SignatureList>> {
    let mut cursor = 0usize;
    let mut signature_lists = Vec::new();

    while cursor < data.len() {
        let current_list_data = &data[cursor..];
        let parsed_list = parse_esl(current_list_data)?;
        let list_size = read_u32_le(&current_list_data[16..20])? as usize;

        anyhow::ensure!(list_size > 0, "signature list size must be greater than zero");

        cursor += list_size;
        signature_lists.push(parsed_list);
    }
    Ok(signature_lists)
}

pub fn parse_esl(data: &[u8]) -> Result<SignatureList> {
    anyhow::ensure!(data.len() >= 28, "signature list is too short to contain a valid header");


    let signature_type = read_guid(&data[0..16])?;
    let signature_list_size = read_u32_le(&data[16..20])? as usize;
    let signature_header_size = read_u32_le(&data[20..24])? as usize;
    let signature_size = read_u32_le(&data[24..28])? as usize;

    anyhow::ensure!(
        data.len() >= signature_list_size,
        "signature list truncated: expected {} bytes, got {}",
        signature_list_size,
        data.len()
    );
    anyhow::ensure!(
        signature_list_size >= 28 + signature_header_size,
        "signature list size is smaller than its header"
    );
    anyhow::ensure!(signature_size >= 16, "signature size must include owner GUID");

    let signature_header_end = 28 + signature_header_size;
    let signature_header = data[28..signature_header_end].to_vec();
    let signature_area = &data[signature_header_end..signature_list_size];
    let signatures = parse_signature_entries(signature_area, signature_size, signature_type)?;

    Ok(SignatureList {
        signature_type,
        signature_header,
        signatures,
    })
}

pub fn parse_x509_certificate<'a>(der: &'a [u8]) -> Result<X509Certificate<'a>> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Błąd dekodowania ASN.1: {:?}", e))
        .context("failed to parse X509 certificate DER")?;

    Ok(cert)
}

fn parse_signature_entries(
    signature_area: &[u8],
    signature_size: usize,
    signature_type: Uuid
) -> Result<Vec<SignatureData>> {
    anyhow::ensure!(
        signature_area.len() % signature_size == 0,
        "signature area is not aligned to signature size"
    );

    let mut signatures = Vec::with_capacity(signature_area.len() / signature_size);
    for signature_bytes in signature_area.chunks_exact(signature_size) {
        let owner = read_guid(&signature_bytes[0..16])?;
        let data = signature_bytes[16..].to_vec();

        signatures.push(SignatureData { owner, data });
    }

    Ok(signatures)
}

fn parse_signature_x509(
    signature_type: Uuid,
    owner: Uuid,
    payload: &[u8]
) -> Result<Option<X509Certificate>> {
    if signature_type != EFI_CERT_X509_GUID {
        return Ok(None);
    }

    Ok(
        Some(
            parse_x509_certificate(payload).with_context(|| {
                format!("failed to parse X509 entry for owner {}", owner)
            })?
        )
    )
}


fn read_u32_le(data: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| anyhow!("invalid u32 byte slice length"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_guid(data: &[u8]) -> Result<Uuid> {
    let bytes: [u8; 16] = data.try_into().map_err(|_| anyhow!("invalid GUID byte slice length"))?;
    Ok(Uuid::from_bytes_le(bytes))
}

fn get_signature_type(sig_type: &Uuid) -> String {
	match (sig_type) {
		&EFI_CERT_X509_GUID => String::from("EFI_CERT_X509"),
		&EFI_CERT_SHA256_GUID => String::from("EFI_CERT_SHA256"),
		&EFI_CERT_RSA2048_GUID => String::from("EFI_CERT_RSA2048"),
		&EFI_CERT_TYPE_PKCS7_GUID => String::from("EFI_CERT_TYPE_PKCS7"),
		_ => String::from("Unknown signature type!"),

	}
}

impl fmt::Display for SecureBootVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for esl in &self.signature_lists {
			writeln!(f, "  Type: {} ", get_signature_type(&esl.signature_type))?;
			writeln!(f, "  Signature header: {}", esl.signatures);
		}
		Ok(())
    }
}