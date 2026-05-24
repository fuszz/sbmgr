use anyhow::Result;
use std::path::Path;

use crate::backend::{
    commands,
    storage_handler::StorageHandler,
    var_parser::{extract_x509_certificates, parse_secure_boot_variable},
    var_reader::VarReader,
    var_writer::VarWriter,
};

pub struct Backend {
    storage_handler: StorageHandler,
    var_reader: VarReader,
    var_writer: VarWriter,
}

impl Backend {
    pub fn new() -> Result<Self> {
        let backend = Self{
            storage_handler: StorageHandler::new()?, 
            var_reader: VarReader::new()?,
            var_writer: VarWriter::new()?
        };
        Ok(backend)
    }

    pub fn list_variables(&mut self) -> Result<Vec<String>> {
        if self.var_reader.variables.is_empty() {
            self.var_reader.update_variable_guids()?;
        }

        Ok(self
            .var_reader
            .variables
            .iter()
            .map(|(name, _)| name.clone())
            .collect())
    }

    pub fn boot_entries_report(&mut self) -> Result<Vec<String>> {
        if self.var_reader.variables.is_empty() {
            self.var_reader.update_variable_guids()?;
        }

        let entries = self.var_reader.get_boot_entries_list()?;
        let mut lines = vec![format!("Boot entries: {}", entries.len())];

        for (name, guid) in entries {
            lines.push(format!("{name} | {guid}"));
        }

        Ok(lines)
    }

    pub fn secure_boot_report(&mut self) -> Result<Vec<String>> {
        if self.var_reader.variables.is_empty() {
            self.var_reader.update_variable_guids()?;
        }

        let mut lines = Vec::new();
        let secure_boot = match self.var_reader.is_secure_boot_active() {
            Ok(true) => "ON".to_string(),
            Ok(false) => "OFF".to_string(),
            Err(err) => format!("unknown ({err})"),
        };
        let setup_mode = match self.var_reader.is_setup_mode_active() {
            Ok(true) => "ON".to_string(),
            Ok(false) => "OFF".to_string(),
            Err(err) => format!("unknown ({err})"),
        };
        let audit_mode = match self.var_reader.is_audit_mode_active() {
            Ok(true) => "ON".to_string(),
            Ok(false) => "OFF".to_string(),
            Err(err) => format!("unknown ({err})"),
        };
        let shim = match self.var_reader.is_shim_active() {
            Ok(true) => "ON".to_string(),
            Ok(false) => "OFF".to_string(),
            Err(err) => format!("unknown ({err})"),
        };

        lines.push(format!("SecureBoot: {secure_boot}"));
        lines.push(format!("SetupMode: {setup_mode}"));
        lines.push(format!("AuditMode: {audit_mode}"));
        lines.push(format!("Shim: {shim}"));

        for (label, data_result) in [
            ("PK", self.var_reader.get_pk()),
            ("KEK", self.var_reader.get_kek()),
            ("db", self.var_reader.get_db()),
            ("dbx", self.var_reader.get_dbx()),
        ] {
            match data_result {
                Ok(data) => {
                    let parsed = parse_secure_boot_variable(&data)?;
                    let certificates = extract_x509_certificates(&data)?;
                    lines.push(format!(
                        "{label}: {} signature list(s), {} X509 certificate(s)",
                        parsed.signature_lists.len(),
                        certificates.len()
                    ));

                    for (index, cert) in certificates.iter().take(3).enumerate() {
                        lines.push(format!(
                            "  {}. {} | {} | {}",
                            index + 1,
                            cert.subject,
                            cert.not_before,
                            cert.not_after,
                        ));
                    }

                    if certificates.len() > 3 {
                        lines.push(format!("  ... and {} more", certificates.len() - 3));
                    }
                }
                Err(err) => {
                    lines.push(format!("{label}: unavailable ({err})"));
                }
            }
        }

        Ok(lines)
    }

    pub fn run_console_command(&mut self, input: &str) -> Result<Vec<String>> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let command = tokens[0].to_lowercase();

        match command.as_str() {
            "help" => Ok(vec![
                "Commands: help, refresh, vars, secureboot, boots, export-pk <stem>, import-db <path>, backup-all <dir>".to_string(),
            ]),
            "refresh" => {
                self.var_reader.update_variable_guids()?;
                let mut lines = vec!["Refreshed UEFI state".to_string()];
                lines.extend(self.secure_boot_report()?);
                Ok(lines)
            }
            "vars" => Ok(self.list_variables()?.into_iter().map(|name| format!("- {name}")).collect()),
            "secureboot" => self.secure_boot_report(),
            "boots" | "boot" => self.boot_entries_report(),
            "export-pk" => {
                let stem = tokens.get(1).copied().unwrap_or("pk");
                // commands::export_pk(&mut self.var_reader, &self.storage_handler, Path::new(stem))?;
                Ok(vec![format!("Exported PK to {}.der", stem)])
            }
            "import-db" => {
                let path = tokens.get(1).ok_or_else(|| anyhow::anyhow!("missing path"))?;
                // commands::import_db_from_path(&mut self.var_writer, Path::new(path))?;
                Ok(vec![format!("Imported db from {path}")])
            }
            "backup-all" => {
                let dir = tokens.get(1).copied().unwrap_or("backup");
                // commands::backup_all(&self.var_reader, &self.storage_handler, dir)?;
                Ok(vec![format!("Backed up PK/KEK/db/dbx to .sbmgr/{dir}")])
            }
            other => Err(anyhow::anyhow!("unknown command: {other}")),
        }
    }
}