mod backend;
mod demo;
mod tui;

fn main() -> anyhow::Result<()> {
    demo::var_gen::run()?;
    Ok(())
}



