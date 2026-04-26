

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
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
		let data = fs::read(file_path)
			.with_context(|| format!("cannot read PK file: {}", file_path))?;
		self.write_pk(&data)
	}

	pub fn write_kek_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let data = fs::read(file_path.as_ref())
			.with_context(|| format!("cannot read KEK file: {}", file_path.as_ref().display()))?;
		self.write_kek(&data)
	}

	pub fn write_db_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let data = fs::read(file_path.as_ref())
			.with_context(|| format!("cannot read db file: {}", file_path.as_ref().display()))?;
		self.write_db(&data)
	}

	pub fn write_dbx_from_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<()> {
		let data = fs::read(file_path.as_ref())
			.with_context(|| format!("cannot read dbx file: {}", file_path.as_ref().display()))?;
		self.write_dbx(&data)
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