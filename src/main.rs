use crate::backend::get_pk_raw_manual;

mod backend;
fn main() {
    match get_pk_raw_manual() {
        Ok(data) => println!("{:?}", data),
        Err(e) => eprintln!("{}", e),
    }
}