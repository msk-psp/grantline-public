//! Explicit CA bundles supplement no ambient TLS settings; verification stays enabled.
use crate::Result;
use std::{fs, io::Read, path::Path};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, parse_pem};

pub fn certificates(env: Option<&str>) -> Result<Option<Vec<Certificate<'static>>>> {
    let Some(key) = env else { return Ok(None) };
    let path = std::env::var(key).map_err(|_| "CA bundle variable is unavailable")?;
    let path = Path::new(&path);
    if !fs::metadata(path)
        .map_err(|_| "Cannot inspect CA bundle")?
        .is_file()
    {
        return Err("CA bundle must be a regular PEM file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "Cannot open CA bundle")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read CA bundle")?;
    if bytes.len() > 1024 * 1024 {
        return Err("CA bundle exceeds limit".into());
    }
    let mut certificates = Vec::new();
    for item in parse_pem(&bytes) {
        match item.map_err(|_| "Invalid PEM CA bundle")? {
            PemItem::Certificate(certificate) => certificates.push(certificate),
            _ => return Err("CA bundle must contain certificates only".into()),
        }
    }
    if certificates.is_empty() {
        return Err("CA bundle has no certificates".into());
    }
    Ok(Some(certificates))
}
pub fn http(env: Option<&str>) -> Result<TlsConfig> {
    let mut config = TlsConfig::builder();
    if let Some(certificates) = certificates(env)? {
        config = config.root_certs(RootCerts::new_with_certs(&certificates));
    }
    Ok(config.build())
}
pub fn postgres(env: Option<&str>) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let Some(certificates) = certificates(env)? else {
        return Ok(tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots());
    };
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(
                certificate.der().to_vec(),
            ))
            .map_err(|_| "Invalid CA certificate")?;
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
}
