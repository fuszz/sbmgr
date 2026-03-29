use efivar;
mod backend;

fn main() {
    let manager = efivar::system();
    println!("{:?}", backend::var_reader::is_sb_active(manager.as_ref()).unwrap())
}