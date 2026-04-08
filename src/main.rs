use crossterm::event::read;
use efivar;
mod backend;
use anyhow::Result;
use virtfw_libefi::efivar::sigdb::EfiSigDB;
fn main() -> Result<()> {
    let mut reader = backend::var_reader::VarReader::default()?;
    reader.update_variable_guids()?;
    println!("{:?}", EfiSigDB::new_from_bytes(&reader.get_dbx()?).unwrap().get_x509_list().len());
    Ok(())
}

