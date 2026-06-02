use crate::backend;
use anyhow::Result;    

pub fn run() -> Result<()> {
    let mut backend =  backend::backend::Backend::new()?;
    let boot_order = backend.var_reader.get_boot_order()?;
    let new_boot_order = backend::boot_handler::change_boot_order(&boot_order, 4)?;
    println!("{:?}", new_boot_order);
    let new_bytes_data: Vec<u8>= new_boot_order.iter().flat_map(|&x| x.to_le_bytes()).collect();
    println!("{:?}", new_bytes_data);
    backend.var_writer.write_boot_order(&new_bytes_data)?;
    Ok(())
}