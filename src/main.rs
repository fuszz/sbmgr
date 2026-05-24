use anyhow::Result;
mod backend;
mod tui;
fn main() -> Result<()> {
    let mut backend = backend::backend::Backend::new();
    Ok(())
}



