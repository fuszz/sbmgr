use anyhow::Result;
mod backend;
mod tui;
fn main() -> Result<()> {
    let mut tui_app = tui::TuiApp::new()?;
    tui_app.run()?;
    Ok(())
}



