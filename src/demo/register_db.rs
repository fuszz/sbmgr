use crate::backend;
use anyhow::Result;
use std::fs;
use uuid::Uuid;

pub fn run() -> Result<()> {
    println!("=== Registering Authorized Signatures Database (db) ===\n");

    // Load certificate from generated artifacts (or use hardcoded path)
    let cert_path = "secure_boot_artifacts/pk-cert.pem";
    let cert_pem = fs::read(cert_path)
        .unwrap_or_else(|_| {
            println!("Warning: Could not read {}, using fallback data", cert_path);
            // Fallback: minimal X509 certificate in PEM format for demo
            r#"-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUa3gLoKVeykvwMxK0fxqhqtMTJk8wDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAeFw0yNjA2MTQx
MTU2MTZaFw0yNzA2MTQxMTU2MTZaMGwxCzAJBgNVBAYTAlBMMREwDwYDVQQKDAhz
Ym1nciBQSzEUMBIGA1UECwwLU2VjdXJlIEJvb3QxNDAyBgNVBAMMK3NibWdyIGdl
bmVyYXRlZCBjZXJ0aWZpY2F0ZSBmb3IgUGxhdGZvcm1LZXkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCvcAfYAibdWzuwiWIqZN1UlnbjdccegbpiBzFG
F9BbiS16sTmb9qKV17LBRWeJqY6cOfPedEAWcUxk62aL74cHZOcfAURTbPJI8ghU
A9+kNRQb4eqW4lLVUX6MWvN6bHlVu+COaxWyeyL35fCZf9JrpZgRYIma2nkJOHOG
RlEyOUn8bc1qDfUg4DBK8JIyDG1/7mXiWl3GldsuwwoFTMdKrJwzko1AQ+iHRtkU
MOHpfw/bsbcwZLxckzL6myvVt7pt1golfM8Vs46EVC2FeQNm8dEErRt5Cr6x3XhF
S9719kJNbj/dChdjiU1YBZ85PQFjGtjANeACHiCw524WEgkCAwEAAaMTMBEwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAaXCbXZCiHxaAEyBdQmfM
o+ntwaTgXMELB/Mv8OkQ8aYdkpTJh/QdUwwU0Whpo3FyDJLmVnp+DJpCILPZqH/P
+v9usbcj64zNgB+4/4hbT08+y2klp5DOO2YpPRMAR+grgUhHII7OelpbdaaZPJFa
sSfJxBiY2VfNshPDDuKuyvSGmnqoxbREeHUt/G75NPU0LR+DOdg0AiZ8EeC/E5uL
+jJzMcMzXHOSEIIXMueY8VNXXiGc6wWj7qadjyuxKOwN7GWF8L87/Lipez3l4D70
iPgw9+zSHz/fyz0tLQ==
-----END CERTIFICATE-----"#.as_bytes().to_vec()
        });

    // Create ESL for db with the certificate
    let mut esl = backend::esl_creator::EfiSigList::new(
        backend::guids::SignatureType::EfiCertX509Guid
    );
    
    // Use a deterministic UUID for the owner
    let owner_uuid = Uuid::parse_str("928907b3-7c9f-074e-9592-9a8fe2768472")?;
    
    esl.add_x509_certificate_to_esl(&cert_pem, owner_uuid)?;
    let esl_bytes = esl.to_bytes();

    println!("Created ESL for db:");
    println!("  ESL Size: {} bytes", esl_bytes.len());
    println!("  Owner UUID: {}", owner_uuid);
    println!("  Certificate source: {}\n", cert_path);

    // Register db
    let mut backend_instance = backend::backend::Backend::new()?;
    backend_instance.var_writer.write_db(&esl_bytes)?;

    println!("✓ Successfully registered db variable\n");

    // Verify the registration by reading it back
    println!("=== Verifying db Registration ===\n");
    
    match backend_instance.var_reader.get_db() {
        Ok(db_data) => {
            match backend::var_parser::parse_esl(&db_data) {
                Ok(esl_parsed) => {
                    println!("Signature Type: {}", backend::var_parser::get_signature_type(&esl_parsed.signature_type));
                    println!("Total entries: {}\n", esl_parsed.signatures.len());
                    for (idx, sig) in esl_parsed.signatures.iter().enumerate() {
                        println!("  Entry {}:", idx + 1);
                        println!("{}", sig);
                    }
                }
                Err(e) => println!("Failed to parse db: {}", e),
            }
        }
        Err(e) => println!("Failed to read db: {}", e),
    }

    Ok(())
}
