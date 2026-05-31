mod backend;
mod demo;
mod tui;

fn main() -> anyhow::Result<()> {
    let mut backend = backend::backend::Backend::new()?; 
    let pk = backend.var_reader.get_pk()?;
    let pk_sb_var = backend::var_parser::parse_secure_boot_variable(&pk)?;
    print!("{}", pk_sb_var);

    println!("===============================");
    let dbx = backend.var_reader.get_dbx()?;
    let dbx_sb_var = backend::var_parser::parse_secure_boot_variable(&dbx)?;
    print!("{}", dbx_sb_var);

    Ok(())
}



