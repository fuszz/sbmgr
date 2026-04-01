use crossterm::event::read;
use efivar;
mod backend;
use anyhow::Result;

fn main() -> Result<()> {
    let mut reader = backend::var_reader::VarReader::default()?;
    reader.update_variable_guids()?;
    println!("{:?}", reader.get_boot_order()?);
    Ok(())
}

