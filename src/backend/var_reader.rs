use std::str::FromStr;
use anyhow::Result;
use efivar::{
    VarManager,
    boot::BootEntry,
    efi,
};
use uuid::Uuid;
use regex::Regex;
use sysinfo;

pub struct VarReader {
    pub manager: Box<dyn VarManager>,
    pub variables: Vec<(String, Uuid)>,
}

impl VarReader {
    pub fn new() -> Result<Self> {
        let mut var_reader = VarReader {
            manager: efivar::system(),
            variables: vec![],
        };
        var_reader.update_variable_guids()?;
        Ok(var_reader)
    }

    pub fn update_variable_guids(&mut self) -> Result<()> {
        self.variables.clear();
        let all_vars = self.manager.get_all_vars()?;
        for var in all_vars {
            self.variables.push((String::from(var.name()), Uuid::from_str(&var.vendor().to_string())?))
        }
        self.variables.sort();
        Ok(())
    }

    pub fn find_variable_guid(&self, var: &str) -> Result<Uuid>{
        let guid = self
            .variables
            .iter()
            .find(|s| s.0.eq(&var))
            .ok_or_else(|| anyhow::anyhow!("variable {} not found", var))?
            .1
            .clone();
        
        Ok(guid)
    }

    pub fn is_secure_boot_active(&self) -> Result<bool> {
        let name = "SecureBoot";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn is_setup_mode_active(&self) -> Result<bool> {
        let name = "SetupMode";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn is_shim_active(&self) -> Result<bool> {
        let os_name = match sysinfo::System::name() {
            Some(name) => name,
            None => return Ok(false),
        };

        if !os_name.contains("Linux") {
            Ok(false)
        } else {
            let current_boot = self.get_current_boot()?;
            if current_boot.len() < 2 {
                return Ok(false);
            }

            let boot_id = u16::from_le_bytes([current_boot[0], current_boot[1]]);
            let boot_entry = match self.get_boot_entry(boot_id) {
                Ok(entry) => entry,
                Err(_) => return Ok(false),
            };

            let file_path_list = match boot_entry.file_path_list.as_ref() {
                Some(path_list) => path_list,
                None => return Ok(false),
            };

            Ok(file_path_list
                .file_path
                .path
                .to_string()
                .contains("shim"))
        }
    }

    pub fn is_audit_mode_active(&self) -> Result<bool> {
        let name = "AuditMode";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn get_pk(&self) -> Result<Vec<u8>> {
        let name = "PK";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        Ok(data)
    }

    pub fn get_kek(&self) -> Result<Vec<u8>> {
        let name = "KEK";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        Ok(data)
    }

    pub fn get_db(&self) -> Result<Vec<u8>> {
        let name = "db";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        Ok(data)
    }

    pub fn get_dbx(&self) -> Result<Vec<u8>> {
        let name = "dbx";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        Ok(data)
    }

    pub fn get_boot_order(&self) -> Result<Vec<u16>> {
        let name = "BootOrder";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        anyhow::ensure!(data.len() % 2 == 0, "Wrong BootOrder variable data length");
        let boot_order_list: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(boot_order_list)
    }

    pub fn get_current_boot(&self) -> Result<Vec<u8>> {
        let name = "BootCurrent";
        let guid = self.find_variable_guid(name)?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, guid))?;
        Ok(data)
    }

    pub fn get_boot_entries_list(&self) -> Result<Vec<(String, Uuid)>> {
        let mut boot_entries_list: Vec<(String, Uuid)> = self.variables
                                    .iter()
                                    .filter(|s| Regex::new(r"^Boot[0-9A-Fa-f]{4}$").unwrap().is_match(&s.0))
                                    .cloned()
                                    .collect();
        boot_entries_list.sort();
        Ok(boot_entries_list)
    }

    pub fn get_boot_entry(&self, boot_id: u16) -> Result<BootEntry> {
        let boot_entry_no: String = format!("Boot{:04X}", boot_id.to_le());
        let guid = self.find_variable_guid(&boot_entry_no)?;        
        let boot_entry = BootEntry::read(
            self.manager.as_ref(),
            &efi::Variable::new_with_vendor(&boot_entry_no, guid),
        )?;
        Ok(boot_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn find_variable_guid_ok() {
        let vr = VarReader {
            manager: efivar::system(),
            variables: vec![
                ("SecureBoot".to_string(), Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
                ("Foo".to_string(), Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
            ],
        };

        let guid = vr.find_variable_guid("Foo").unwrap();
        assert_eq!(guid, Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap());
    }

    #[test]
    fn find_variable_guid_err() {
        let vr = VarReader {
            manager: efivar::system(),
            variables: vec![],
        };

        assert!(vr.find_variable_guid("NotExist").is_err());
    }

    #[test]
    fn get_boot_entries_list_filters_and_sorts() {
        let vr = VarReader {
            manager: efivar::system(),
            variables: vec![
                ("Boot000A".to_string(), Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap()),
                ("Boot0001".to_string(), Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()),
                ("Other".to_string(), Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
                ("Boot0002".to_string(), Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            ],
        };

        let list = vr.get_boot_entries_list().unwrap();
        let names: Vec<String> = list.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(names, vec!["Boot0001".to_string(), "Boot0002".to_string(), "Boot000A".to_string()]);
    }
}
