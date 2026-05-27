use anyhow::{Context, Result};
use std::{
    env,
    fs::{create_dir_all, write},
    path::{Path, PathBuf},
};

use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use backend::{
    auth_creator::create_auth_data_data,
    esl_creator::EfiSigList,
    guids::SignatureType,
    secret_creator::{
        create_rsa_2048_private_key,
        create_rsa_2048_public_key,
        create_sha256_digest,
        create_x509_certificate,
    },
    var_writer::VarWriter,
};

mod backend;
mod tui;

#[derive(Clone, Copy)]
enum DemoEslKind {
    X509,
    Sha256OfCert,
}

struct DemoVariable {
    stem: &'static str,
    var_name: &'static str,
    common_name: &'static str,
    organization: &'static str,
    organizational_unit: &'static str,
    is_ca: bool,
    esl_kind: DemoEslKind,
}

struct DemoBundle {
    private_key_pem: Vec<u8>,
    public_key_pem: Vec<u8>,
    certificate_pem: Vec<u8>,
    esl_bytes: Vec<u8>,
    auth_bytes: Vec<u8>,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);

    if let Some(command) = args.next() {
        if command == "demo" {
            let output_dir = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("secure_boot_artifacts"));
            let apply_to_uefi = args.any(|arg| arg == "--apply");

            generate_demo_artifacts(&output_dir)?;

            if apply_to_uefi {
                apply_demo_artifacts(&output_dir)?;
            }

            println!("Generated demo Secure Boot artifacts in {}", output_dir.display());
            if apply_to_uefi {
                println!("Applied demo values to UEFI variables PK, KEK, db and dbx");
            }

            return Ok(());
        }
    }

    let _backend = backend::backend::Backend::new()?;
    Ok(())
}

fn generate_demo_artifacts(output_dir: &Path) -> Result<()> {
    create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    for variable in demo_variables() {
        let bundle = build_demo_bundle(&variable)?;
        write_bundle(output_dir, variable.stem, &bundle)?;
    }

    Ok(())
}

fn apply_demo_artifacts(output_dir: &Path) -> Result<()> {
    let mut writer = VarWriter::new()?;

    writer.write_pk(&read_artifact(output_dir, "pk.auth")?)?;
    writer.write_kek(&read_artifact(output_dir, "kek.auth")?)?;
    writer.write_db(&read_artifact(output_dir, "db.auth")?)?;
    writer.write_dbx(&read_artifact(output_dir, "dbx.auth")?)?;

    Ok(())
}

fn demo_variables() -> [DemoVariable; 4] {
    [
        DemoVariable {
            stem: "pk",
            var_name: "PK",
            common_name: "sbmgr Demo Platform Key",
            organization: "sbmgr Demo",
            organizational_unit: "Platform Key",
            is_ca: true,
            esl_kind: DemoEslKind::X509,
        },
        DemoVariable {
            stem: "kek",
            var_name: "KEK",
            common_name: "sbmgr Demo Key Exchange Key",
            organization: "sbmgr Demo",
            organizational_unit: "Key Exchange Key",
            is_ca: true,
            esl_kind: DemoEslKind::X509,
        },
        DemoVariable {
            stem: "db",
            var_name: "db",
            common_name: "sbmgr Demo Allowed Certificate",
            organization: "sbmgr Demo",
            organizational_unit: "Allowed DB Entry",
            is_ca: false,
            esl_kind: DemoEslKind::X509,
        },
        DemoVariable {
            stem: "dbx",
            var_name: "dbx",
            common_name: "sbmgr Demo Revocation Certificate",
            organization: "sbmgr Demo",
            organizational_unit: "DBX Revocation Entry",
            is_ca: false,
            esl_kind: DemoEslKind::Sha256OfCert,
        },
    ]
}

fn build_demo_bundle(variable: &DemoVariable) -> Result<DemoBundle> {
    let private_key_pem = create_rsa_2048_private_key()?;
    let public_key_pem = create_rsa_2048_public_key(private_key_pem.clone())?;
    let certificate_pem = build_certificate(variable, &private_key_pem, &public_key_pem)?;
    let esl_bytes = build_esl(variable.esl_kind, &certificate_pem)?;
    let auth_bytes = create_auth_data_data(
        &private_key_pem,
        &certificate_pem,
        &esl_bytes,
        variable.var_name,
    )?;

    Ok(DemoBundle {
        private_key_pem,
        public_key_pem,
        certificate_pem,
        esl_bytes,
        auth_bytes,
    })
}

fn build_certificate(
    variable: &DemoVariable,
    private_key_pem: &[u8],
    public_key_pem: &[u8],
) -> Result<Vec<u8>> {
    let key_pair = KeyPair::from_pem(std::str::from_utf8(private_key_pem)?)?;
    let issuer = Issuer::new(CertificateParams::default(), key_pair);
    let distinguished_name = build_distinguished_name(
        variable.common_name,
        variable.organization,
        variable.organizational_unit,
    );

    create_x509_certificate(
        public_key_pem,
        issuer,
        distinguished_name,
        variable.is_ca,
        OffsetDateTime::now_utc(),
        OffsetDateTime::now_utc() + Duration::days(365),
    )
}

fn build_esl(kind: DemoEslKind, certificate_pem: &[u8]) -> Result<Vec<u8>> {
    let owner = Uuid::new_v4();

    match kind {
        DemoEslKind::X509 => {
            let mut esl = EfiSigList::new(SignatureType::EfiCertX509Guid);
            esl.add_x509_certificate_to_esl(certificate_pem, owner)?;
            Ok(esl.to_bytes())
        }
        DemoEslKind::Sha256OfCert => {
            let cert_der = pem::parse(certificate_pem)?.contents().to_vec();
            let digest = create_sha256_digest(&cert_der);
            let mut esl = EfiSigList::new(SignatureType::EfiCertSha256Guid);
            esl.add_sha256_checksum_to_esl(&digest, owner)?;
            Ok(esl.to_bytes())
        }
    }
}

fn build_distinguished_name(
    common_name: &str,
    organization_name: &str,
    organizational_unit_name: &str,
) -> DistinguishedName {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CountryName, "PL");
    distinguished_name.push(DnType::OrganizationName, organization_name);
    distinguished_name.push(DnType::OrganizationalUnitName, organizational_unit_name);
    distinguished_name.push(DnType::CommonName, common_name);
    distinguished_name
}

fn write_bundle(output_dir: &Path, stem: &str, bundle: &DemoBundle) -> Result<()> {
    write(output_dir.join(format!("{stem}-private.pem")), &bundle.private_key_pem)?;
    write(output_dir.join(format!("{stem}-public.pem")), &bundle.public_key_pem)?;
    write(output_dir.join(format!("{stem}-cert.pem")), &bundle.certificate_pem)?;
    write(output_dir.join(format!("{stem}.esl")), &bundle.esl_bytes)?;
    write(output_dir.join(format!("{stem}.auth")), &bundle.auth_bytes)?;
    Ok(())
}

fn read_artifact(output_dir: &Path, file_name: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(output_dir.join(file_name))?)
}



