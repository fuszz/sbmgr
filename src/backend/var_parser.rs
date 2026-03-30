use std::mem::size_of;
use x509_parser::prelude::*;
use std::ptr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EfiSignatureList {
    pub signature_type: [u8; 16], // GUID (np. EFI_CERT_X509_GUID)
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EfiSignatureData {
    pub signature_owner: [u8; 16], // GUID właściciela
    // signature_data: [u8; signature_size - 16] <- tu jest certyfikat
}

fn parse_signature_entries(entries_raw: &[u8], sig_size: usize) {
    let mut offset = 0;
    while offset + sig_size <= entries_raw.len() {
        let entry = &entries_raw[offset..offset + sig_size];
        
        // Pierwsze 16 bajtów to GUID właściciela (np. Microsoft)
        let owner = &entry[..16];
        // Reszta to właściwy certyfikat X.509
        let cert_der = &entry[16..];

        // Parsowanie metadanych certyfikatu
        match parse_x509_certificate(cert_der) {
            Ok((_, cert)) => {
                let tbs = &cert.tbs_certificate;
                println!("  Wystawca: {}", tbs.issuer);
                println!("  Podmiot:  {}", tbs.subject);
                println!("  Ważność:  {} do {}", tbs.validity.not_before, tbs.validity.not_after);
            }
            Err(e) => eprintln!("  Błąd parsowania X.509: {:?}", e),
        }

        offset += sig_size;
    }
}

pub fn parse_uefi_signature_list(data: &[u8]) {
    let mut offset = 0;

    while offset + size_of::<EfiSignatureList>() <= data.len() {
        // Mapujemy nagłówek listy
        let list = unsafe { &*(data[offset..].as_ptr() as *const EfiSignatureList) };
        
        println!("Typ (GUID): {:?}", list.signature_type);
        println!("Rozmiar listy: {}", list.signature_list_size);
        println!("Rozmiar sygnatury: {}", list.signature_size);

        // Obliczamy gdzie zaczynają się dane (za nagłówkiem i opcjonalnym SignatureHeader)
        let data_start = offset + size_of::<EfiSignatureList>() + list.signature_header_size as usize;
        let data_end = offset + list.signature_list_size as usize;
        let signature_data_raw = &data[data_start..data_end];

        // Iterujemy po wpisach wewnątrz tej konkretnej listy
        parse_signature_entries(signature_data_raw, list.signature_size as usize);

        // Przechodzimy do kolejnej listy (jeśli istnieje)
        offset += list.signature_list_size as usize;
    }
}

pub fn parse(data: &[u8]) {
    if data.len() < std::mem::size_of::<EfiSignatureList>() { return; }

    // Bezpieczne czytanie z nieodpowiednio wyrównanego adresu
    let header: EfiSignatureList = unsafe {
        ptr::read_unaligned(data.as_ptr() as *const EfiSignatureList)
    };

    println!("{:?}", header);
}