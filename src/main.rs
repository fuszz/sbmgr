use efivar;
mod backend;

fn main() {
    let manager = efivar::system();
    let kek = backend::var_reader::get_db(manager.as_ref());
    println!("{:?}", backend::var_parser::VariableContent::parse_variable(&kek.unwrap()));
}

