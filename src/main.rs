use anyhow::Result;
mod backend;
mod tui;
fn main() -> Result<()> {
    let sh = backend::storage_handler::StorageHandler::new();

    Ok(())
}




