use crossterm::event::read;
use u16;
use efivar;
mod backend;
use anyhow::Result;
use virtfw_libefi::efivar::{sigdb::EfiSigDB, types::EfiVar};
fn main() -> Result<()> {
    let mut reader = backend::var_reader::VarReader::default()?;
    reader.update_variable_guids()?;
println!(
    "{:04X}", 
    u16::from_le_bytes(
        reader.get_current_boot().unwrap()[0..2]
            .try_into()
            .unwrap()
    )
);    
reader.get_current_boot();
println!("{}", reader.is_shim_active()?);
backend::os::get_os_info();
    Ok(())

}

