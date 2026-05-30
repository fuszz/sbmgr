mod backend;
mod demo;
mod tui;

fn main() -> anyhow::Result<()> {
    let mut backend = backend::backend::Backend::new()?; 
    let pk = backend.var_reader.get_pk()?;
    let pk_sb_var = backend::var_parser::parse_secure_boot_variable(&pk)?;
    println!("{}", pk_sb_var);
    Ok(())
}



