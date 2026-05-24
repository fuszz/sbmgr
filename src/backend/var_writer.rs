use anyhow::Result;
use efivar::{
	VarManager,
	efi::{Variable, VariableFlags},
};
use uuid::Uuid;
use crate::backend::guids::*;

pub struct VarWriter {
	pub manager: Box<dyn VarManager>,
}

impl VarWriter {
	pub fn new() -> Result<Self> {
		Ok(Self {
			manager: efivar::system(),
		})
	}

	pub fn write_pk(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("PK", EFI_GLOBAL_VARIABLE_GUID, data)
	}

	pub fn write_kek(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("KEK", EFI_GLOBAL_VARIABLE_GUID, data)
	}

	pub fn write_db(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("db", EFI_IMAGE_SECURITY_DATABASE_GUID, data)
	}

	pub fn write_dbx(&mut self, data: &[u8]) -> Result<()> {
		self.write_authenticated_var("dbx", EFI_IMAGE_SECURITY_DATABASE_GUID, data)
	}

	fn write_authenticated_var(&mut self, name: &str, vendor: Uuid, data: &[u8]) -> Result<()> {
		let attrs: VariableFlags = VariableFlags::from_bits_retain(EFI_PK_VARIABLE_ATTRIBUTES);
		let variable = Variable::new_with_vendor(name, vendor);

		self.manager
			.write(&variable, attrs, data)?;

		Ok(())
	}
}