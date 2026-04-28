

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::UserDirs;
use efivar::{
	VarManager,
	efi::{Variable, VariableFlags},
};
use uuid::Uuid;

pub struct VarWriter {
	pub manager: Box<dyn VarManager>,
}

impl VarWriter {
	pub fn new() -> Result<Self> {
		Ok(Self {
			manager: efivar::system(),
		})
	}

	pub fn write_pk_from_file(&mut self, file_path: &str) -> Result<()> {
		let resolved_path = self.resolve_auth_input_path(Path::new(file_path), "PK");
		let data = fs::read(&resolved_path)
			.with_context(|| format!("cannot read PK file: {}", resolved_path.display()))?;
		self.write_pk(&data)
	}

	pub fn write_kek_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let resolved_path = self.resolve_auth_input_path(file_path.as_ref(), "KEK");
		let data = fs::read(&resolved_path)
			.with_context(|| format!("cannot read KEK file: {}", resolved_path.display()))?;
		self.write_kek(&data)
	}

	pub fn write_db_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let resolved_path = self.resolve_auth_input_path(file_path.as_ref(), "db");
		let data = fs::read(&resolved_path)
			.with_context(|| format!("cannot read db file: {}", resolved_path.display()))?;
		self.write_db(&data)
	}

	pub fn write_dbx_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let resolved_path = self.resolve_auth_input_path(file_path.as_ref(), "dbx");
		let data = fs::read(&resolved_path)
			.with_context(|| format!("cannot read dbx file: {}", resolved_path.display()))?;
		self.write_dbx(&data)
	}

	fn resolve_auth_input_path(&self, input: &Path, default_stem: &str) -> PathBuf {
		if input.exists() {
			return input.to_path_buf();
		}

		let home_dir = UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf());

		if !input.is_absolute() {
			let cwd_candidate = PathBuf::from(input);
			if cwd_candidate.exists() {
				return cwd_candidate;
			}

			if let Some(home) = &home_dir {
				let home_candidate = home.join(input);
				if home_candidate.exists() {
					return home_candidate;
				}
			}
		}

		if input.extension().is_none() {
			let stem = if input.as_os_str().is_empty() {
				default_stem.to_string()
			} else {
				input.to_string_lossy().into_owned()
			};

			let auth_name = format!("{}.auth", stem);

			let cwd_auth = PathBuf::from(&auth_name);
			if cwd_auth.exists() {
				return cwd_auth;
			}

			if let Some(home) = &home_dir {
				let home_auth = home.join(&auth_name);
				if home_auth.exists() {
					return home_auth;
				}
				return home_auth;
			}

			return cwd_auth;
		}

		if input.is_absolute() {
			input.to_path_buf()
		} else if let Some(home) = home_dir {
			home.join(input)
		} else {
			input.to_path_buf()
		}
	}

	pub fn write_pk(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("PK", Self::efi_global_variable_guid(), data)
	}

	pub fn write_kek(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("KEK", Self::efi_global_variable_guid(), data)
	}

	pub fn write_db(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("db", Self::efi_image_security_database_guid(), data)
	}

	pub fn write_dbx(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("dbx", Self::efi_image_security_database_guid(), data)
	}

	fn write_authenticated_var(&mut self, name: &str, vendor: Uuid, data: &[u8]) -> Result<()> {
		let attrs = Self::auth_var_attributes();
		let variable = Variable::new_with_vendor(name, vendor);

		self.manager
			.write(&variable, attrs, data)?;

		Ok(())
	}

	fn efi_global_variable_guid() -> Uuid {
		Uuid::parse_str("8be4df61-93ca-11d2-aa0d-00e098032b8c")
			.expect("invalid EFI global variable GUID")
	}

	fn efi_image_security_database_guid() -> Uuid {
		Uuid::parse_str("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
			.expect("invalid EFI image security database GUID")
	}

	fn auth_var_attributes() -> VariableFlags {
		VariableFlags::NON_VOLATILE
			| VariableFlags::BOOTSERVICE_ACCESS
			| VariableFlags::RUNTIME_ACCESS
			| VariableFlags::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
	}
}