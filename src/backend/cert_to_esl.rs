use anyhow::Result;
use std::fs;
use std::io::Write;
use uuid::Uuid;
use x509_parser::prelude::parse_x509_pem;

// GUID dla certyfikatów X.509 w UEFI: a5c059a1-94e4-4aa7-87b5-ab155c2bf072
// UEFI zapisuje początkowe sekcje GUID w formacie Little-Endian.
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];

pub fn cert_to_efi_sig_list(cert_path: &str, esl_path: &str) -> Result<()> {
    // 1. Generowanie identyfikatora właściciela (odpowiednik -g "$(uuidgen)")
    let owner_guid = Uuid::new_v4();
    let owner_guid_bytes = owner_guid.to_bytes_le(); // UEFI wymaga Little-Endian dla GUID

    // 2. Wczytanie certyfikatu i wyciągnięcie surowych bajtów (DER)
    let cert_pem = fs::read_to_string(cert_path)?;
    let cert_der = match parse_x509_pem(cert_pem.as_bytes()) {
        Ok((_remaining, pem)) => pem.contents.to_vec(), // Jeśli plik to PEM, dekoduj do DER
        Err(_) => fs::read(cert_path)?,                     // Jeśli nie, załóż, że to już jest DER
    };

    // 3. Obliczanie rozmiarów struktur
    let signature_size: u32 = 16 + cert_der.len() as u32; // 16 bajtów na GUID właściciela + rozmiar certyfikatu
    let signature_list_size: u32 = 28 + signature_size;   // 28 bajtów na nagłówek EFI_SIGNATURE_LIST + signature_size
    let signature_header_size: u32 = 0u32;

    // 4. Budowanie binarnego pliku ESL
    let mut esl_data = Vec::with_capacity(signature_list_size as usize);

    // -- Nagłówek EFI_SIGNATURE_LIST --
    esl_data.write_all(&EFI_CERT_X509_GUID)?;
    esl_data.write_all(&signature_list_size.to_le_bytes())?;
    esl_data.write_all(&signature_header_size.to_le_bytes())?;
    esl_data.write_all(&signature_size.to_le_bytes())?;

    // -- Dane EFI_SIGNATURE_DATA --
    esl_data.write_all(&owner_guid_bytes)?;
    esl_data.write_all(&cert_der)?;

    // 5. Zapis do pliku
    fs::write(esl_path, esl_data)?;

    Ok(())
}