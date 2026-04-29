mod backend;
mod tui;
use anyhow::Result;
fn main() -> Result<()> {
    let creator = backend::var_creator::VarCreator::new();
    creator.create_key_pair("TestKeyPair", "TestKeyPair");

    tui::run();
    Ok(())
}



