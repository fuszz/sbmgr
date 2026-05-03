use anyhow::Result;

use crate::backend::{storage_handler::StorageHandler, var_reader::VarReader, var_writer::VarWriter};

pub struct Backend {
    storage_handler: StorageHandler,
    var_reader: VarReader,
    var_writer: VarWriter,
}

impl Backend {
    pub fn new() -> Result<Self> {
        let backend = Self{
            storage_handler: StorageHandler::new(), 
            var_reader: VarReader::new()?,
            var_writer: VarWriter::new()?
        };
        Ok(backend)
    }

    pub fn list_variables(&self) -> Result<Vec<String>> {
        let mock = vec![String::from("Zmienna 1"), 
            String::from("Zmienna 2"),
            String::from("Zmienna 3")
            ];
        Ok(mock)
    }
}