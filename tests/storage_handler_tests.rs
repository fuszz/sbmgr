use anyhow::Result;
use sbmgr::backend;

#[test]
pub fn test_file_writing_and_reading() -> Result<()> {
    let sh = backend::storage_handler::StorageHandler::new();
    let content = "This is some test content";
    sh.write_to_file("123", "txt", content.as_bytes())?;
    let test_content = sh.read_from_file("123", "txt")?;
    assert_eq!(test_content, content.as_bytes());
    Ok(())
}