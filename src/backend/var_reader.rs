use std::{any, env::var};

use efivar::{
    VarManager, boot::{self, BootEntry}, efi
};
use anyhow::{self, Context, Result, ensure};
use hex;

pub fn is_secure_boot_active(manager: &dyn VarManager) -> Result<bool> {
    let (data, _) = manager.read(&efi::Variable::new("SecureBoot"))?;
    if data[0] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn is_setup_mode_active(manager: &dyn VarManager) -> Result<bool> {
    let (data, _) = manager.read(&efi::Variable::new("SetupMode"))?;
    if data[0] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn is_audit_mode_active(manager: &dyn VarManager) -> Result<bool> {
    let (data, _) = manager.read(&efi::Variable::new("AuditMode"))?;
    if data[0] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn get_pk(manager: &dyn VarManager) -> Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("PK"))?;
    Ok(data)
}

pub fn get_kek(manager: &dyn VarManager) -> Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("KEK"))?;
    Ok(data)
}

pub fn get_db(manager: &dyn VarManager) -> Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbDefault"))?;
    Ok(data)
}

pub fn get_dbx(manager: &dyn VarManager) -> Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbxDefault"))?;
    Ok(data)
}

pub fn get_boot_order(manager: &dyn VarManager) -> Result<Vec<u16>> {
    let (data, _) = manager
        .read(&efi::Variable::new("BootOrder"))
        .context("Unable to read BootOrder variable")?;
    anyhow::ensure!(data.len() % 2 == 0, "Wrong BootOrder variable data length");
    let boot_order_list: Vec<u16> = data.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
    Ok(boot_order_list)
}

pub fn get_boot_entry(manager: &dyn VarManager, boot_id: u16) -> Result<BootEntry> {
    let boot_order = get_boot_order(manager)?;
    ensure!(boot_order.contains(&boot_id), "Provided boot_id does not exist");
    let boot_entry_no: String = format!("{:04X}", boot_id.to_le());
    let boot_entry = BootEntry::read(manager, &efi::Variable::new(&format!("{}{}","Boot", boot_entry_no)))?;
    Ok(boot_entry)
}
