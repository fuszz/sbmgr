use std::{default, mem::size_of};
use ratatui::text::ToLine;
use x509_parser::{nom::ToUsize, prelude::*};
use std::ptr;
use anyhow::{Result, ensure};
use uuid::Uuid;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SignatureData {
    pub guid: Uuid, 
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SignatureList {
    pub guid: Uuid,
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
    pub signatures: Vec<SignatureData>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableContent {
    pub signature_lists: Vec<SignatureList>,
}

impl SignatureData {
    pub fn parse_signature_data(data: &Vec<u8>, start: &usize, signature_size: &usize) -> Result<Self> {
        let mut signature_data: SignatureData = Self::default();
        signature_data.guid = Uuid::from_bytes_le(data[*start..*start+16].try_into()?);
        signature_data.data = data[*start+16..].try_into()?;
        Ok(signature_data)
    }
}

impl SignatureList {

    pub fn parse_signature_list(data: &Vec<u8>, offset: &mut usize) -> Result<Self> {
        let mut signature_list: SignatureList = Self::default();
        let mut start = *offset;
        signature_list.guid = Uuid::from_bytes_le(data[start..start+16].try_into()?);
        start += 16;
        signature_list.signature_list_size = u32::from_le_bytes(data[start..start+4].try_into()?);
        start+=4;
        signature_list.signature_header_size= u32::from_le_bytes(data[start..start+4].try_into()?);
        start+=4;
        signature_list.signature_size= u32::from_le_bytes(data[start..start+4].try_into()?);
        start+=4;
        
        while start < *offset + signature_list.signature_list_size.to_usize() {
            signature_list.signatures.push(
                SignatureData::parse_signature_data(&data, &start, &signature_list.signature_size.to_usize())?
            );
            start += signature_list.signature_size.to_usize();
        }

        *offset += start;
        Ok(signature_list)
    }
}

impl VariableContent {
    pub fn parse_variable(data: &Vec<u8>) -> Result<Self> {
        let mut offset: usize = 0;
        let mut variable_content: VariableContent = VariableContent::default(); 
        
        while offset < data.len() {
            variable_content.signature_lists.push(
                SignatureList::parse_signature_list(&data, &mut offset)?
            );
    }
    Ok(variable_content)
}
}