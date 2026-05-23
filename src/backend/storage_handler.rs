use std::{fs, path::PathBuf};
use directories::UserDirs;
use anyhow::Result;
pub struct StorageHandler {
    storage_dir: PathBuf,
}

impl StorageHandler {
    pub fn new() -> Self {
        let user_dirs = UserDirs::new().expect("Unable to find current user's home directory");
        let proj_dirs = user_dirs.home_dir().join(".sbmgr");
        let storage_dir = proj_dirs.to_path_buf();
        fs::create_dir_all(proj_dirs).expect("Unable to create directory");
        Self { storage_dir }
    }

    pub fn read_from_file(&self, file_path: &str, file_suffix: &str) -> Result<Vec<u8>> {
        let file_path_buf = self.storage_dir.join(format!("{}.{}", file_path, file_suffix));
        Ok(fs::read(&file_path_buf)?)
    }

    pub fn write_to_file(&self, file_path: &str, file_suffix: &str, contents: &[u8]) -> Result<()> {
        let file_path_buf = self.storage_dir.join(format!("{}.{}", file_path, file_suffix));
        fs::write(&file_path_buf, contents)?;
        Ok(())
    }
}
