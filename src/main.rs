mod backend;
mod tui;
use anyhow::Result;
fn main() -> Result<()> {
    backend::esl_to_auth::sign_efi_sig_list("/root/.sbmgr/123.key", 
    "/root/.sbmgr/123.crt",
    "PK", "/root/.sbmgr/123.esl", "/root/.sbmgr/123.auth")?;

    //tui::run();
    Ok(())
}



