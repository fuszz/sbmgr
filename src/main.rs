use efivar;
mod backend;

fn main() {
    let manager = efivar::system();
    let kek = backend::var_reader::get_kek_raw(manager.as_ref());

    println!("{:?}", kek);
    backend::var_parser::parse(&kek.unwrap());
}

