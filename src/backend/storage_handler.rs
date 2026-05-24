use std::{ fs::{create_dir_all, read, write}, path::{ Path, PathBuf } };
use directories::UserDirs;
use anyhow::{ Result, Context };
pub struct StorageHandler {
    storage_dir: PathBuf,
}

impl StorageHandler {
    pub fn new() -> Result<Self> {
        let user_dirs = UserDirs::new().context("Unable to find current user's home directory")?;
        let proj_dirs = user_dirs.home_dir().join(".sbmgr");
        let storage_dir = proj_dirs.to_path_buf();
        create_dir_all(&storage_dir)
            .with_context(|| format!("Failed to create storage directory at {:?}", storage_dir))?;
        Ok(Self { storage_dir })
    }

    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    pub fn read_from_file<P: AsRef<Path>>(
        &self,
        file_name: P,
        file_suffix: &str
    ) -> Result<Vec<u8>> {
        let file_name_buf = self.storage_dir.join(file_name).with_extension(file_suffix);
        Ok(read(&file_name_buf)?)
    }

    pub fn write_to_file<P: AsRef<Path>>(
        &self,
        file_name: P,
        file_suffix: &str,
        contents: &[u8]
    ) -> Result<()> {
        let file_name_buf = self.storage_dir.join(file_name).with_extension(file_suffix);
        write(&file_name_buf, contents)?;
        Ok(())
    }
}
