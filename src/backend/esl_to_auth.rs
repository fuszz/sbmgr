use anyhow::{Context, Result};
use chrono::{Datelike, Timelike, Utc};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use std::fs;
use std::io::Write;

// GUID dla zmiennej globalnej UEFI (używany dla zmiennych PK i KEK)
// 8BE4DF61-93CA-11D2-AA0D-00E098032B8C (w formacie Little-Endian)
const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 
    0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];

// Atrybuty zmiennej Secure Boot: NV (Non-Volatile) | BS (BootService) | RT (Runtime) | AW (TimeBasedAuthWrite)
// 0x00000001 | 0x00000002 | 0x00000004 | 0x00000020 = 0x27
const EFI_VARIABLE_ATTRIBUTES: u32 = 0x00000027;

/// Generuje strukturę EFI_TIME opartą na obecnym czasie UTC
fn generate_efi_time() -> [u8; 16] {
    let now = Utc::now();
    let mut time_buf = [0u8; 16];
    
    // Year (u16 LE), Month (u8), Day (u8), Hour (u8), Minute (u8), Second (u8), Pad1 (u8)
    time_buf[0..2].copy_from_slice(&(now.year() as u16).to_le_bytes());
    time_buf[2] = now.month() as u8;
    time_buf[3] = now.day() as u8;
    time_buf[4] = now.hour() as u8;
    time_buf[5] = now.minute() as u8;
    time_buf[6] = now.second() as u8;
    time_buf[7] = 0; // Pad1
    
    // Nanosecond (u32 LE), TimeZone (i16 LE), Daylight (u8), Pad2 (u8)
    time_buf[8..12].copy_from_slice(&0u32.to_le_bytes()); 
    time_buf[12..14].copy_from_slice(&0i16.to_le_bytes()); // 0 = UTC
    time_buf[14] = 0; // Daylight
    time_buf[15] = 0; // Pad2
    
    time_buf
}

pub fn sign_efi_sig_list(
    private_key_path: &str,
    cert_path: &str,
    var_name: &str,
    esl_path: &str,
    auth_path: &str,
) -> Result<()> {
    // 1. Wczytywanie klucza i certyfikatu
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(private_key_path)?;
    let cert = X509::from_pem(&cert_bytes).context("Błąd certyfikatu")?;
    let pkey = PKey::private_key_from_pem(&key_bytes).context("Błąd klucza")?;
    let esl_data = fs::read(esl_path).context("Błąd odczytu ESL")?;

    let efi_time = generate_efi_time();

    // 2. Przygotowanie bufora do autoryzacji (To jest to, co faktycznie podpisujemy)
    // Bufor: Nazwa Zmiennej (UTF-16LE) + GUID Zmiennej + Atrybuty + EFI_TIME + Dane ESL
    let mut auth_buffer = Vec::new();
    
    // Konwersja nazwy (np. "PK") na UTF-16LE bez null-terminatora na końcu
    for c in var_name.encode_utf16() {
        auth_buffer.extend_from_slice(&c.to_le_bytes());
    }
    
    auth_buffer.write_all(&EFI_GLOBAL_VARIABLE_GUID)?;
    auth_buffer.write_all(&EFI_VARIABLE_ATTRIBUTES.to_le_bytes())?;
    auth_buffer.write_all(&efi_time)?;
    auth_buffer.write_all(&esl_data)?;

    // 3. Tworzenie podpisu PKCS#7 (odłączonego) za pomocą OpenSSL
    let certs = Stack::new()?;
    let flags = Pkcs7Flags::BINARY | Pkcs7Flags::DETACHED;
    let pkcs7 = Pkcs7::sign(&cert, &pkey, &certs, &auth_buffer, flags)
        .context("Błąd podczas podpisywania PKCS#7")?;
    
    let pkcs7_der = pkcs7.to_der()?;

    // 4. Składanie pliku .auth (EFI_VARIABLE_AUTHENTICATION_2 + Payload)
    let mut auth_file = Vec::new();
    
    // --- EFI_VARIABLE_AUTHENTICATION_2 ---
    auth_file.write_all(&efi_time)?; // Znacznik czasu
    
    // --- WIN_CERTIFICATE_UEFI_GUID ---
    let cert_type_guid: [u8; 16] = [ // EFI_CERT_TYPE_PKCS7_GUID
        0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49,
        0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
    ];
    let win_cert_len = (24 + pkcs7_der.len()) as u32; // 24 = nagłówek WIN_CERT + GUID
    
    auth_file.write_all(&win_cert_len.to_le_bytes())?; // dwLength
    auth_file.write_all(&0x0200u16.to_le_bytes())?;    // wRevision
    auth_file.write_all(&0x0EF1u16.to_le_bytes())?;    // wCertificateType (WIN_CERT_TYPE_EFI_GUID)
    auth_file.write_all(&cert_type_guid)?;             // CertType (PKCS7)
    
    // Podpis PKCS7
    auth_file.write_all(&pkcs7_der)?;
    
    // Na samym końcu dodajemy oryginalny payload (.esl)
    auth_file.write_all(&esl_data)?;

    // 5. Zapis pliku
    fs::write(auth_path, auth_file)?;

    Ok(())
}