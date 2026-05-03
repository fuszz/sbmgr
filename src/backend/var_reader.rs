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
        Ok(VarReader {
            manager: efivar::system(),
            variables: vec![],
        })
    }

    pub fn update_variable_guids(&mut self) -> Result<()> {
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
        if ! sysinfo::System::name().unwrap().contains("Linux") {
            Ok(false)
        } else {
            let boot_id = u16::from_le_bytes(
                    self.get_current_boot()?[0..2]
                    .try_into()
                    .unwrap()
                );
            if self.get_boot_entry(boot_id)?
                .file_path_list
                .as_ref()
                .expect("Cannot find path") 
                .file_path.path
                .to_string().
                contains("shim") {
                    Ok(true)
                } else {
                    Ok(false)
                }      
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
