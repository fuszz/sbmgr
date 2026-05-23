use anyhow::{anyhow, Context, Result};
use hex::encode;
use openssl::{hash::MessageDigest, x509::X509};
use uuid::Uuid;

use crate::backend::guids::EFI_CERT_X509_GUID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509CertificateInfo {
	pub subject: String,
	pub issuer: String,
	pub serial_number: String,
	pub not_before: String,
	pub not_after: String,
	pub sha256_fingerprint: String,
	pub der_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
	pub owner: Uuid,
	pub data: Vec<u8>,
	pub x509: Option<X509CertificateInfo>,
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

pub fn parse_x509_certificate(der: &[u8]) -> Result<X509CertificateInfo> {
	let cert = X509::from_der(der).context("failed to parse X509 certificate DER")?;

	Ok(X509CertificateInfo {
		subject: format_name(cert.subject_name()),
		issuer: format_name(cert.issuer_name()),
		serial_number: cert
			.serial_number()
			.to_bn()
			.context("failed to convert certificate serial number")?
			.to_hex_str()
			.context("failed to format certificate serial number")?
			.to_string(),
		not_before: cert.not_before().to_string(),
		not_after: cert.not_after().to_string(),
		sha256_fingerprint: encode(
			cert.digest(MessageDigest::sha256())
				.context("failed to compute certificate fingerprint")?
		),
		der_size: der.len(),
	})
}

pub fn parse_secure_boot_variable(data: &[u8]) -> Result<SecureBootVariable> {
	Ok(SecureBootVariable {
		signature_lists: parse_signature_lists(data)?,
	})
}

pub fn parse_signature_lists(data: &[u8]) -> Result<Vec<SignatureList>> {
	let mut cursor = 0usize;
	let mut lists = Vec::new();

	while cursor < data.len() {
		let list = parse_signature_list(&data[cursor..])?;
		let list_size = read_u32_le(&data[cursor + 16..cursor + 20])? as usize;
		cursor += list_size;
		lists.push(list);
	}

	Ok(lists)
}

pub fn parse_signature_list(data: &[u8]) -> Result<SignatureList> {
	ensure_signature_list_header(data)?;

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
	let signature_area = &data[signature_header_end..signature_list_size];
	anyhow::ensure!(
		signature_area.len() % signature_size == 0,
		"signature area is not aligned to signature size"
	);

	let mut signatures = Vec::new();
	for signature_bytes in signature_area.chunks_exact(signature_size) {
		let owner = read_guid(&signature_bytes[0..16])?;
		let payload = signature_bytes[16..].to_vec();
		let x509 = if signature_type == EFI_CERT_X509_GUID {
			Some(parse_x509_certificate(&payload).with_context(|| {
				format!("failed to parse X509 entry for owner {}", owner)
			})?)
		} else {
			None
		};

		signatures.push(SignatureData {
			owner,
			data: payload,
			x509,
		});
	}

	Ok(SignatureList {
		signature_type,
		signature_header: data[28..signature_header_end].to_vec(),
		signatures,
	})
}

pub fn extract_x509_certificates(data: &[u8]) -> Result<Vec<X509CertificateInfo>> {
	let variable = parse_secure_boot_variable(data)?;
	let mut certificates = Vec::new();

	for list in variable.signature_lists {
		for signature in list.signatures {
			if let Some(cert) = signature.x509 {
				certificates.push(cert);
			}
		}
	}

	Ok(certificates)
}

fn ensure_signature_list_header(data: &[u8]) -> Result<()> {
	anyhow::ensure!(
		data.len() >= 28,
		"signature list is too short to contain a valid header"
	);
	Ok(())
}

fn read_u32_le(data: &[u8]) -> Result<u32> {
	let bytes: [u8; 4] = data
		.try_into()
		.map_err(|_| anyhow!("invalid u32 byte slice length"))?;
	Ok(u32::from_le_bytes(bytes))
}

fn read_guid(data: &[u8]) -> Result<Uuid> {
	let bytes: [u8; 16] = data
		.try_into()
		.map_err(|_| anyhow!("invalid GUID byte slice length"))?;
	Ok(Uuid::from_bytes_le(bytes))
}

fn format_name(name: &openssl::x509::X509NameRef) -> String {
	let parts: Vec<String> = name
		.entries()
		.map(|entry| {
			let key = entry.object().nid().short_name().unwrap_or("OID");
			let value = entry
				.data()
				.as_utf8()
				.map(|value| value.to_string())
				.unwrap_or_else(|_| encode(entry.data().as_slice()));
			format!("{}={}", key, value)
		})
		.collect();

	if parts.is_empty() {
		String::from("<empty>")
	} else {
		parts.join(", ")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_RSA_SHA256};

	fn generate_test_cert_der() -> Vec<u8> {
		let mut params = CertificateParams::default();
		let mut dn = DistinguishedName::new();
		dn.push(DnType::CommonName, "sbmgr.test");
		params.distinguished_name = dn;
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

		let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).expect("key generation");
		let cert = params.self_signed(&key_pair).expect("certificate generation");
		let cert_pem = cert.pem();
		let cert = X509::from_pem(cert_pem.as_bytes()).expect("pem parsing");
		cert.to_der().expect("der encoding")
	}

	fn build_signature_list(cert_der: &[u8]) -> Vec<u8> {
		let signature_size = 16 + cert_der.len();
		let list_size = 28 + signature_size;
		let owner = Uuid::nil().to_bytes_le();

		let mut data = Vec::new();
		data.extend_from_slice(&EFI_CERT_X509_GUID.to_bytes_le());
		data.extend_from_slice(&(list_size as u32).to_le_bytes());
		data.extend_from_slice(&0u32.to_le_bytes());
		data.extend_from_slice(&(signature_size as u32).to_le_bytes());
		data.extend_from_slice(&owner);
		data.extend_from_slice(cert_der);
		data
	}

	#[test]
	fn parses_x509_certificate_info() {
		let cert_der = generate_test_cert_der();
		let info = parse_x509_certificate(&cert_der).expect("certificate parsing");

		assert!(info.subject.contains("sbmgr.test"));
		assert!(info.issuer.contains("sbmgr.test"));
		assert_eq!(info.der_size, cert_der.len());
		assert_eq!(info.sha256_fingerprint.len(), 64);
	}

	#[test]
	fn parses_secure_boot_signature_list() {
		let cert_der = generate_test_cert_der();
		let list = build_signature_list(&cert_der);

		let parsed = parse_secure_boot_variable(&list).expect("variable parsing");
		assert_eq!(parsed.signature_lists.len(), 1);
		assert_eq!(parsed.signature_lists[0].signatures.len(), 1);
		assert!(parsed.signature_lists[0].signatures[0].x509.is_some());
	}
}

