use anyhow::{ anyhow, Context, Result };
use hex::encode;
use uuid::Uuid;
use x509_parser::prelude::*;
use crate::backend::guids::*;
use sha2::{ Digest, Sha256 };
use std::fmt::{ Write };
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignatureData {
    pub owner: Uuid,
    pub data: Vec<u8>,
    pub is_x509: bool,
    pub is_rsa2048: bool,
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
        let is_x509 = if signature_type == EFI_CERT_X509_GUID { true } else { false };
        let is_rsa2048 = if signature_type == EFI_CERT_RSA2048_GUID { true } else { false };
        signatures.push(SignatureData { owner, data, is_x509, is_rsa2048 });
    }

    Ok(signatures)
}

fn format_x509(cert_bytes: &[u8]) -> Result<String> {
    let mut buffer = String::new();
    match parse_x509_certificate(&cert_bytes) {
        Ok(cert) => {
            writeln!(&mut buffer, "      Subject: {}", cert.subject())?;
            writeln!(&mut buffer, "      Issuer: {}", cert.issuer())?;
            writeln!(&mut buffer, "      Not before: {}", cert.validity().not_before)?;
            writeln!(&mut buffer, "      Not after: {}", cert.validity().not_after)?;
            writeln!(&mut buffer, "      Checksum: {}", compute_fingerprint(&cert_bytes)?)?;
        }
        Err(e) => {
            return Err(e);
        }
    }
    Ok(buffer)
}

fn format_sha_256(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut buffer = String::new();
    write!(&mut buffer, "      SHA-256: ")?;

    for b in bytes {
        write!(&mut buffer, "{:02x}", b)?;
    }
    writeln!(&mut buffer)?;

    Ok(buffer)
}

fn format_rsa_2048(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut buffer = String::new();
    write!(&mut buffer, "      RSA-2048: ")?;

    for (i, b) in bytes.iter().enumerate() {
        write!(&mut buffer, "{:02x}", b)?;
        if i < bytes.len() - 1 {
            write!(&mut buffer, ":")?;
        }
    }
    writeln!(&mut buffer)?;
    write!(&mut buffer, "      Fignerprint (SHA-256): ")?;
    writeln!(&mut compute_fingerprint(bytes)?)?;

    Ok(buffer)
}

fn compute_fingerprint(rsa_bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut hasher = Sha256::new();
    hasher.update(rsa_bytes);
    let hash = hasher.finalize();
    let mut buffer = String::new();
    write!(&mut buffer, "SHA256 ")?;

    for b in hash.iter() {
        write!(&mut buffer, "{:02x}", b)?;
    }
    Ok(buffer)
}

fn read_u32_le(data: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| anyhow!("invalid u32 byte slice length"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_guid(data: &[u8]) -> Result<Uuid> {
    let bytes: [u8; 16] = data.try_into().map_err(|_| anyhow!("invalid GUID byte slice length"))?;
    Ok(Uuid::from_bytes_le(bytes))
}

pub fn get_signature_type(sig_type: &Uuid) -> String {
    match sig_type {
        &EFI_CERT_X509_GUID => String::from("EFI_CERT_X509"),
        &EFI_CERT_SHA256_GUID => String::from("EFI_CERT_SHA256"),
        &EFI_CERT_RSA2048_GUID => String::from("EFI_CERT_RSA2048"),
        &EFI_CERT_TYPE_PKCS7_GUID => String::from("EFI_CERT_TYPE_PKCS7"),
        _ => String::from("Unknown signature type!"),
    }
}

impl fmt::Display for SignatureData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "    Owner UUID: {} ", &self.owner)?;
        if self.is_x509 {
            match format_x509(&self.data) {
                Ok(cert_string) => writeln!(f, "{}", cert_string)?,
                Err(err_msg) => writeln!(f, "X509 cert parsing error: {}", err_msg)?,
            }
        } else if self.is_rsa2048 {
            match format_rsa_2048(&self.data) {
                Ok(cert_string) => writeln!(f, "{}", cert_string)?,
                Err(err_msg) => writeln!(f, "RSA2048 public key parsing error: {}", err_msg)?,
            }
        } else {
            match format_sha_256(&self.data) {
                Ok(cert_string) => writeln!(f, "{}", cert_string)?,
                Err(err_msg) => writeln!(f, "SHA256 checksum parsing error:: {}", err_msg)?,
            }
        }

        Ok(())
    }
}

impl fmt::Display for SignatureList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sig_id = 0;
        for signature in &self.signatures {
            writeln!(f, "{} no: {} ", get_signature_type(&self.signature_type), sig_id)?;
            writeln!(f, "  {}", signature)?;
            sig_id += 1;
        }
        Ok(())
    }
}

impl fmt::Display for SecureBootVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for esl in &self.signature_lists {
            writeln!(f, "EFI Signature List: \n {}", esl)?;
        }
        Ok(())
    }
}
