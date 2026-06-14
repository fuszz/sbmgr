use crate::backend;
use anyhow::Result;    

pub fn run() -> Result<()> {
    let backend = backend::backend::Backend::new()?;
    
    println!("=== Secure Boot Status ===");
    println!("Secure Boot active: {}", backend.var_reader.is_secure_boot_active()?);
    println!("Setup Mode active: {}", backend.var_reader.is_setup_mode_active()?);
    println!("Shim active: {}", backend.var_reader.is_shim_active()?);
    println!();
    
    println!("=== Platform Key (PK) ===");
    match backend.var_reader.get_pk() {
        Ok(a) => {
            match backend::var_parser::parse_esl(&a) {
                Ok(esl) => {
                    println!("Signature Type: {}", backend::var_parser::get_signature_type(&esl.signature_type));
                    println!("Total entries: {}\n", esl.signatures.len());
                    for (idx, sig) in esl.signatures.iter().enumerate() {
                        println!("  Entry {}:", idx + 1);
                        println!("{}", sig);
                    }
                }
                Err(e) => println!("Failed to parse PK: {}", e),
            }
        }
        Err(_) => println!("No PK registered"),
    }
    
    println!();
    println!("=== Key Exchange Key (KEK) ===");
    match backend.var_reader.get_kek() {
        Ok(a) => {
            match backend::var_parser::parse_esl(&a) {
                Ok(esl) => {
                    println!("Signature Type: {}", backend::var_parser::get_signature_type(&esl.signature_type));
                    println!("Total entries: {}\n", esl.signatures.len());
                    for (idx, sig) in esl.signatures.iter().enumerate() {
                        println!("  Entry {}:", idx + 1);
                        println!("{}", sig);
                    }
                }
                Err(e) => println!("Failed to parse KEK: {}", e),
            }
        }
        Err(_) => println!("No KEK registered"),
    }
    
    println!();
    println!("=== Authorized Signatures Database (db) ===");
    match backend.var_reader.get_db() {
        Ok(a) => {
            match backend::var_parser::parse_esl(&a) {
                Ok(esl) => {
                    println!("Signature Type: {}", backend::var_parser::get_signature_type(&esl.signature_type));
                    println!("Total entries: {}\n", esl.signatures.len());
                    for (idx, sig) in esl.signatures.iter().enumerate() {
                        println!("  Entry {}:", idx + 1);
                        println!("{}", sig);
                    }
                }
                Err(e) => println!("Failed to parse db: {}", e),
            }
        }
        Err(_) => println!("No db registered"),
    }
    
    println!();
    println!("=== Forbidden Signatures Database (dbx) ===");
    match backend.var_reader.get_dbx() {
        Ok(a) => {
            match backend::var_parser::parse_esl(&a) {
                Ok(esl) => {
                    println!("Signature Type: {}", backend::var_parser::get_signature_type(&esl.signature_type));
                    println!("Total entries: {}\n", esl.signatures.len());
                    for (idx, sig) in esl.signatures.iter().enumerate() {
                        println!("  Entry {}:", idx + 1);
                        println!("{}", sig);
                    }
                }
                Err(e) => println!("Failed to parse dbx: {}", e),
            }
        }
        Err(_) => println!("No dbx registered"),
    }
    
    Ok(())
}