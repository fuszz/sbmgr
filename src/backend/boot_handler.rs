use anyhow::Result;
use efivar::efi;
use std::process::Command;


pub fn change_boot_order(boot_order: &[u16], target_id: u16) -> Result<Vec<u16>> {
    let mut new_order = boot_order.to_vec();
    
    if let Some(index) = new_order.iter().position(|&id| id == target_id) {
        let item = new_order.remove(index);
        new_order.insert(0, item);
    } else {
        new_order.insert(0, target_id);
    }
    
    Ok(new_order)
}

pub fn register_bootloader(disk: &str, partition: &str, efi_path: &str, label: &str) -> Result<()>{
    let status = Command::new("efibootmgr")
        .args(&[
            "--create",
            "--disk", disk,             // np. "/dev/nvme0n1"
            "--part", partition,        // np. "1" (dla ESP)
            "--loader", efi_path,       // np. "\\EFI\\custom\\bootloader.efi"
            "--label", label,           // np. "Mój Bootloader"
        ])
        .status()?;

    println!("Successfully registered bootloader with label {} and EFI path {}", label, efi_path);
    Ok(())
}