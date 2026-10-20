pub mod approval;
pub mod auth;
mod cache;
pub mod cli;
pub mod clickhouse;
pub mod commands;
pub mod config;
pub mod console;
pub mod engine;
pub mod graph;
pub mod integrations;
#[cfg(unix)]
pub mod migration;
pub mod model;
pub mod notify;
pub mod planner;
pub mod postgres;
pub mod probe;
pub mod recent;
pub mod s3;
pub mod snapshot;
pub mod tls;
pub mod web;
#[cfg(unix)]
pub mod workflow;

pub type Result<T> = std::result::Result<T, String>;

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    #[test]
    fn hash_and_signature_hex_preserve_existing_encoding() {
        assert_eq!(super::hex(&[0, 1, 15, 16, 255]), "00010f10ff");
        assert_eq!(
            crate::integrations::sha(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            super::hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // RFC 4231 test case 1, independent of the crate's own implementation.
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            super::hex(&mac.finalize().into_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
