use std::{any, env::var, str::FromStr};

use anyhow::{self, Context, Result, ensure};
use efivar::{
    VarManager,
    boot::{self, BootEntry},
    efi,
};
use uuid::Uuid;
use regex::Regex;

pub struct VarReader {
    pub manager: Box<dyn VarManager>,
    pub variables: Vec<String>,
}

impl VarReader {
    pub fn default() -> Result<Self> {
        Ok(VarReader {
            manager: efivar::system(),
            variables: vec![],
        })
    }

    pub fn update_variable_guids(&mut self) -> Result<()> {
        let all_vars = self.manager.get_all_vars()?;
        for var in all_vars {
            self.variables.push(String::from(var.to_string()));
        }
        Ok(())
    }

    pub fn find_variable_name(&self, var: &str) -> Result<(&str, &str)>{
        let full_name = self
            .variables
            .iter()
            .find(|s| s.contains(&var))
            .ok_or_else(|| anyhow::anyhow!("variable {} not found", var))?;

        let (name, guid) = full_name
            .split_once('-')
            .ok_or_else(|| anyhow::anyhow!("Unable to parse variable name"))?;
        
        Ok((name, guid))
    }

    pub fn is_secure_boot_active(&self) -> Result<bool> {
        let (name, guid) = self.find_variable_name("SecureBoot")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn is_setup_mode_active(&self) -> Result<bool> {
        let (name, guid) = self.find_variable_name("SetupMode")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn is_audit_mode_active(&self) -> Result<bool> {
        let (name, guid) = self.find_variable_name("AuditMode")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        if data[0] == 1 { Ok(true) } else { Ok(false) }
    }

    pub fn get_pk(&self) -> Result<Vec<u8>> {
        let (name, guid) = self.find_variable_name("PK")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        Ok(data)
    }

    pub fn get_kek(&self) -> Result<Vec<u8>> {
        let (name, guid) = self.find_variable_name("KEK")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        Ok(data)
    }

    pub fn get_db(&self) -> Result<Vec<u8>> {
        let (name, guid) = self.find_variable_name("db")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;
        Ok(data)
    }

    pub fn get_dbx(&self) -> Result<Vec<u8>> {
        let (name, guid) = self.find_variable_name("dbx")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;        
        Ok(data)
    }

    pub fn get_boot_order(&self) -> Result<Vec<u16>> {
        let (name, guid) = self.find_variable_name("BootOrder")?;
        let (data, _) = self.manager.read(&efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?))?;   
        anyhow::ensure!(data.len() % 2 == 0, "Wrong BootOrder variable data length");
        let boot_order_list: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(boot_order_list)
    }

    pub fn get_boot_entries_list(&self) -> Result<Vec<String>> {
        let mut boot_entries_list: Vec<String> = self.variables
                                    .iter()
                                    .filter(|s| Regex::new(r"^Boot[0-9A-Fa-f]{4}-[0-9a-fA-F-]{36}$").unwrap().is_match(s))
                                    .cloned()
                                    .collect();
        boot_entries_list.sort();
        Ok(boot_entries_list)
    }

    pub fn get_boot_entry(&self, boot_id: u16) -> Result<BootEntry> {
        let boot_entry_no: String = format!("Boot{:04X}", boot_id.to_le());
        let (name, guid) = self.find_variable_name(&boot_entry_no)?;        
        let boot_entry = BootEntry::read(
            self.manager.as_ref(),
            &efi::Variable::new_with_vendor(name, Uuid::from_str(guid)?),
        )?;
        Ok(boot_entry)
    }
}
