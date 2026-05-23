use anyhow::Result;
use std::path::Path;

use crate::backend::storage_handler::StorageHandler;
use crate::backend::var_reader::VarReader;
use crate::backend::var_writer::VarWriter;
use uuid::Uuid;

/// Reprezentuje wysokopoziomowe komendy, które może wywołać UI.
pub enum Command {
    ExportPk { out_stem: String },
    ImportDb { input_path: String },
    ListBootEntries,
    BackupAll { dir: String },
}

/// Zunifikowany wynik komendy (prosty, rozszerzalny).
pub enum CommandResult {
    Ok,
    Bytes(Vec<u8>),
    Strings(Vec<String>),
    BootEntries(Vec<(String, Uuid)>),
}

/// Wykonaj komendę, delegując do `VarReader`/`VarWriter`/`StorageHandler`.
///
/// Uwaga: moduł nie inicjalizuje samodzielnie `VarManager` — oczekuje, że
/// caller przekaże istniejące instancje (np. z `Backend`). Dzięki temu łatwiej
/// testować logikę (można podstawiać mocki).
pub fn execute(
    cmd: Command,
    reader: &mut VarReader,
    writer: &mut VarWriter,
    storage: &StorageHandler,
) -> Result<CommandResult> {
    match cmd {
        Command::ExportPk { out_stem } => {
            let data = reader.get_pk()?;
            storage.write_to_file(&out_stem, "der", &data)?;
            Ok(CommandResult::Ok)
        }
        Command::ImportDb { input_path } => {
            // VarWriter ma już helpera `write_db_from_file` — odczyta plik i zapisze do UEFI
            writer.write_db_from_file(&input_path)?;
            Ok(CommandResult::Ok)
        }
        Command::ListBootEntries => {
            let list = reader.get_boot_entries_list()?;
            Ok(CommandResult::BootEntries(list))
        }
        Command::BackupAll { dir } => {
            // zapisujemy kopie PK/KEK/db/dbx w katalogu wewnątrz storage (~/.sbmgr/<dir>/...)
            let pk = reader.get_pk()?;
            let kek = reader.get_kek()?;
            let db = reader.get_db()?;
            let dbx = reader.get_dbx()?;

            storage.write_to_file(&format!("{}/pk", dir), "der", &pk)?;
            storage.write_to_file(&format!("{}/kek", dir), "der", &kek)?;
            storage.write_to_file(&format!("{}/db", dir), "der", &db)?;
            storage.write_to_file(&format!("{}/dbx", dir), "der", &dbx)?;

            Ok(CommandResult::Ok)
        }
    }
}

/// Convenience wrappers for callers that prefer direct helpers.
pub fn export_pk(reader: &mut VarReader, storage: &StorageHandler, out_stem: &Path) -> Result<()> {
    let data = reader.get_pk()?;
    storage.write_to_file(out_stem.to_str().unwrap_or("pk"), "der", &data)?;
    Ok(())
}

pub fn import_db_from_path(writer: &mut VarWriter, input: &Path) -> Result<()> {
    writer.write_db_from_file(input)
}

pub fn list_boot_entries(reader: &VarReader) -> Result<Vec<(String, Uuid)>> {
    reader.get_boot_entries_list()
}

pub fn backup_all(reader: &VarReader, storage: &StorageHandler, dir: &str) -> Result<()> {
    let pk = reader.get_pk()?;
    let kek = reader.get_kek()?;
    let db = reader.get_db()?;
    let dbx = reader.get_dbx()?;

    storage.write_to_file(&format!("{}/pk", dir), "der", &pk)?;
    storage.write_to_file(&format!("{}/kek", dir), "der", &kek)?;
    storage.write_to_file(&format!("{}/db", dir), "der", &db)?;
    storage.write_to_file(&format!("{}/dbx", dir), "der", &dbx)?;

    Ok(())
}
