use crate::backend::storage_handler::StorageHandler;
use crate::backend::guids::*;
use anyhow::Result;
use openssl::{x509, pkey, stack, pkcs7};
use std::io::Write;
use chrono::{Datelike, Timelike, Utc};

pub fn generate_efi_time() -> [u8; 16] {
    let now = Utc::now();
    let year = (now.year() as u16).to_le_bytes();
    [
        year[0], year[1],     // Year (u16 LE)
        now.month() as u8,    // Month
        now.day() as u8,      // Day
        now.hour() as u8,     // Hour
        now.minute() as u8,   // Minute
        now.second() as u8,   // Second
        0,                    // Pad1
        0, 0, 0, 0,           // Nanosecond (u32 LE)
        0, 0,                 // TimeZone (i16 LE, 0 = UTC)
        0,                    // Daylight
        0,                    // Pad2
    ]
}

pub fn prepare_auth_buffer(var_name: &str, esl_data: &[u8], efi_time: &[u8; 16]) -> Result<Vec<u8>> {
    let mut auth_buffer: Vec<u8> = Vec::new();
    // Konwersja nazwy (np. "PK") na UTF-16LE bez null-terminatora na końcu
    for c in var_name.encode_utf16() {
        auth_buffer.extend_from_slice(&c.to_le_bytes());
    }
    auth_buffer.write_all(&EFI_GLOBAL_VARIABLE_GUID.to_bytes_le())?;
    auth_buffer.write_all(&EFI_PK_VARIABLE_ATTRIBUTES.to_le_bytes())?;
    auth_buffer.write_all(efi_time)?;
    auth_buffer.write_all(&esl_data)?;
    Ok(auth_buffer)
}

pub fn create_auth_data_data(
    key_bytes: &[u8],
    cert_bytes: &[u8],
    esl_data: &[u8],
    var_name: &str,
) -> Result<Vec<u8>> {
    let cert = x509::X509::from_pem(&cert_bytes)?;
    let pkey = pkey::PKey::private_key_from_pem(&key_bytes)?;
    let efi_time = generate_efi_time();

    let auth_buffer: Vec<u8> = prepare_auth_buffer(var_name, &esl_data, &efi_time)?;

    let certs = stack::Stack::new()?;
    let flags = pkcs7::Pkcs7Flags::BINARY | pkcs7::Pkcs7Flags::DETACHED;
    let pkcs7 = pkcs7::Pkcs7::sign(&cert, &pkey, &certs, &auth_buffer, flags)?;
    let pkcs7_der = pkcs7.to_der()?;

    let mut auth_data = Vec::new();
    auth_data.write_all(&efi_time)?; // Znacznik czasu

    let cert_type_guid = EFI_CERT_TYPE_PKCS7_GUID.to_bytes_le();
    let win_cert_len = (24 + pkcs7_der.len()) as u32; // 24 = nagłówek WIN_CERT + GUID

    auth_data.write_all(&win_cert_len.to_le_bytes())?; // dwLength
    auth_data.write_all(&(0x0200u16).to_le_bytes())?; // wRevision
    auth_data.write_all(&(0x0ef1u16).to_le_bytes())?; // wCertificateType (WIN_CERT_TYPE_EFI_GUID)
    auth_data.write_all(&cert_type_guid)?; // CertType (PKCS7)
    auth_data.write_all(&pkcs7_der)?;

    auth_data.write_all(&esl_data)?;
    Ok(auth_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{pkey::PKey, rsa::Rsa, x509::{X509NameBuilder, X509}, asn1::Asn1Time, hash::MessageDigest, x509::X509Builder, nid::Nid};

    #[test]
    fn prepare_auth_buffer_has_expected_prefix() {
        let esl = b"ESLTEST";
        let efi_time = generate_efi_time();
        let buf = prepare_auth_buffer("PK", esl, &efi_time).expect("prepare");

        // 'P' 'K' in UTF-16LE
        assert_eq!(&buf[0..4], &[0x50, 0x00, 0x4B, 0x00]);

        // next 16 bytes = EFI_GLOBAL_VARIABLE_GUID
        assert_eq!(&buf[4..20], &EFI_GLOBAL_VARIABLE_GUID.to_bytes_le());

        // next 4 bytes = attributes
        let attrs = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(attrs, EFI_PK_VARIABLE_ATTRIBUTES);

        // next 16 bytes = efi_time
        assert_eq!(&buf[24..40], &efi_time);

        // tail ends with esl
        assert_eq!(&buf[40..], esl);
    }

    #[test]
    fn create_auth_data_data_includes_esl() {
        // generate RSA key and a self-signed certificate
        let rsa = Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        // subject name
        let mut name_builder = X509NameBuilder::new().expect("name builder");
        name_builder.append_entry_by_nid(Nid::COMMONNAME, "sbmgr.test").expect("append cn");
        let name = name_builder.build();

        let mut builder = X509Builder::new().expect("x509 builder");
        builder.set_version(2).expect("set version");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&pkey).expect("set pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("not before");
        let not_after = Asn1Time::days_from_now(365).expect("not after");
        builder.set_not_before(&not_before).expect("set nb");
        builder.set_not_after(&not_after).expect("set na");
        builder.sign(&pkey, MessageDigest::sha256()).expect("sign");
        let cert = builder.build();

        let cert_pem = cert.to_pem().expect("cert pem");
        let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

        let esl = b"ESL-DATA";
        let auth = create_auth_data_data(&key_pem, &cert_pem, esl, "PK").expect("create auth");

        // auth ends with esl data
        assert!(auth.ends_with(esl));

        // auth should be larger than esl + pkcs7 header (24) + efi_time (16)
        assert!(auth.len() > esl.len() + 24 + 16);
    }
}