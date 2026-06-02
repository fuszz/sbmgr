use crate::backend::boot_handler;
use anyhow::Result;

pub fn run() -> Result<()> {
    boot_handler::register_bootloader("/dev/sda", "1", "\\EFI\\sbmgr\\boot.efi", "Secure Boot Manager Demo entry")?;
    Ok(())
}