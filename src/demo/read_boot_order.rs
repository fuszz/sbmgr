use crate::backend;
use anyhow::Result;
pub fn run() -> Result<()> {
    
    let mut backend = backend::backend::Backend::new()?;
    let boot_order = backend.var_reader.get_boot_order()?;
    println!("{:?}", boot_order);
    let boot_entries: Vec<(String, uuid::Uuid)> = backend.var_reader.get_boot_entries_list()?;
    println!("{:?}", &boot_entries);
    let first_boot_entry = backend.var_reader.get_boot_entry(boot_order[0])?;
    println!("{:?}", first_boot_entry);
    Ok(())
}