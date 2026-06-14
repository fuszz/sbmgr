mod backend;
mod demo;

fn main() -> anyhow::Result<()> {
    // demo::var_gen::run()?;
    demo::read_sb_vars::run()?;
    demo::register_custom_bootloader::run()?;
    demo::register_db::run()?;
    Ok(())
}





