use efivar::{
    VarManager, efi
};

pub fn is_sb_active(manager: &dyn VarManager) -> efivar::Result<bool> {
    let (data, _) = manager.read(&efi::Variable::new("SecureBoot"))?;
    if data[0] == 1 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn get_pk_raw(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("PK"))?;
    Ok(data)
}

pub fn get_kek_raw(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("KEK"))?;
    Ok(data)
}

pub fn get_db_raw(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbDefault"))?;
    Ok(data)
}

pub fn get_dbx_raw(manager: &dyn VarManager) -> efivar::Result<Vec<u8>> {
    let (data, _) = manager.read(&efi::Variable::new("dbxDefault"))?;
    Ok(data)
}
