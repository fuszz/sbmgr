use efivar;
mod backend;

fn main() {
    let manager = efivar::system();
    let kek = backend::var_reader::get_boot_entry(manager.as_ref(), [0x0,0x5]);
    println!("{:?}", kek.unwrap());
}

