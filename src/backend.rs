use std::{fs, io};

pub fn get_pk_raw_manual() -> io::Result<Vec<u8>> {
    // Pełna ścieżka do zmiennej PK w efivarfs
    let path = "/sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c";

    // Odczytujemy surowe bajty z pliku
    let mut raw_content = fs::read(path)?;

    
    if raw_content.len() > 4 {
        // Usuwamy pierwsze 4 bajty atrybutów i zwracamy resztę
        Ok(raw_content.split_off(4))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Plik zmiennej EFI jest za krótki (brak danych)",
        ))
    }
}