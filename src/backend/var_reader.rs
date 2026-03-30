use efivar::{
    VarManager, efi, 
    boot::BootEntry,
};
use core::str;
use hex;

pub fn is_sb_active(manager: &dyn VarManager) -> efivar::Result<bool> {
    let (data, _) = manager.read(&efi::Variable::new("SecureBoot"))?;
    if data[0] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn get_pk(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("PK"))?;
    Ok(data)
}

pub fn get_kek(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("KEK"))?;
    Ok(data)
}

pub fn get_db(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbDefault"))?;
    Ok(data)
}

pub fn get_dbx(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbxDefault"))?;
    Ok(data)
}

pub fn get_boot_order(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("BootOrder"))?;
    Ok(data)
}

pub fn get_boot_entry(manager: &dyn VarManager, boot_id: [u8; 2]) -> efivar::Result<BootEntry> {
    if get_boot_order(manager).unwrap().len() <
    let boot_entry = BootEntry::read(manager, &efi::Variable::new(&format!("{}{}","Boot", hex::encode(boot_id))));
    boot_entry
}
