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
    auth_buffer.write_all(efi_time);
    auth_buffer.write_all(&esl_data)?;
    Ok(auth_buffer)
}

pub fn create_auth_file(
    private_key_path: &str,
    cert_path: &str,
    var_name: &str,
    esl_path: &str,
    auth_path: &str,
    sh: &StorageHandler
) -> Result<()> {
    let cert_bytes = sh.read_from_file(cert_path, "cer")?;
    let key_bytes = sh.read_from_file(private_key_path, "der")?;
    let esl_data = sh.read_from_file(esl_path, "esl")?;
    let cert = x509::X509::from_pem(&cert_bytes)?;
    let pkey = pkey::PKey::private_key_from_pem(&key_bytes)?;
    let efi_time = generate_efi_time();

    // 2. Przygotowanie bufora do autoryzacji (To jest to, co faktycznie podpisujemy)
    // Bufor: Nazwa Zmiennej (UTF-16LE) + GUID Zmiennej + Atrybuty + EFI_TIME + Dane ESL
    let auth_buffer: Vec<u8> = prepare_auth_buffer(var_name, &esl_data, &efi_time)?;

    // 3. Tworzenie podpisu PKCS#7 (odłączonego) za pomocą OpenSSL
    let certs = stack::Stack::new()?;
    let flags = pkcs7::Pkcs7Flags::BINARY | pkcs7::Pkcs7Flags::DETACHED;
    let pkcs7 = pkcs7::Pkcs7::sign(&cert, &pkey, &certs, &auth_buffer, flags)?;
    let pkcs7_der = pkcs7.to_der()?;

    // 4. Składanie pliku .auth (EFI_VARIABLE_AUTHENTICATION_2 + Payload)
    let mut auth_file = Vec::new();

    // --- EFI_VARIABLE_AUTHENTICATION_2 ---
    auth_file.write_all(&efi_time)?; // Znacznik czasu

    // --- WIN_CERTIFICATE_UEFI_GUID ---
    let cert_type_guid: [u8; 16] = [
        // EFI_CERT_TYPE_PKCS7_GUID
        0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
    ];
    let win_cert_len = (24 + pkcs7_der.len()) as u32; // 24 = nagłówek WIN_CERT + GUID

    auth_file.write_all(&win_cert_len.to_le_bytes())?; // dwLength
    auth_file.write_all(&(0x0200u16).to_le_bytes())?; // wRevision
    auth_file.write_all(&(0x0ef1u16).to_le_bytes())?; // wCertificateType (WIN_CERT_TYPE_EFI_GUID)
    auth_file.write_all(&cert_type_guid)?; // CertType (PKCS7)
    auth_file.write_all(&pkcs7_der)?;

    // Na samym końcu dodajemy oryginalny payload (.esl)
    auth_file.write_all(&esl_data)?;
    sh.write_to_file(auth_path, "auth",  &auth_file);
    Ok(())
}