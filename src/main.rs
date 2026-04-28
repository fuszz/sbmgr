mod backend;
// mod tui;
use anyhow::Result;
fn main() -> Result<()> {
    let creator = backend::var_creator::VarCreator::new();
    creator.create_key_pair("TestKeyPair", "/root/123")?;
    creator.create_pk_file("TestPK", "/root/123.crt", "/root/123PK.auth")?;
    let mut writer = backend::var_writer::VarWriter::new()?;
    writer.write_pk_from_file("/root/123PK.auth")?;
    // tui::run()
    Ok(())
}


