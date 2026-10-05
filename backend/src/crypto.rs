//! Byte-for-byte compatible with packages/core/src/crypto/envelope.ts: HKDF-SHA256 subkeys per
//! purpose, AES-256-GCM sealed as version (1) · iv (12) · tag (16) · ciphertext, with AAD.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result, bail};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

const VERSION: u8 = 1;
const IV_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

#[derive(Clone, Copy)]
pub enum Purpose {
    SigningKeys,
}

impl Purpose {
    fn info(self) -> &'static [u8] {
        match self {
            Purpose::SigningKeys => b"signing-keys",
        }
    }
}

pub fn parse_root_key(value: &str) -> Result<Vec<u8>> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .context("HANDSTAMP_SECRET_KEY must be base64")?;
    if key.len() < 32 {
        bail!("HANDSTAMP_SECRET_KEY must decode to at least 32 bytes");
    }
    Ok(key)
}

pub fn derive_key(root: &[u8], purpose: Purpose) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"handstamp"), root)
        .expand(purpose.info(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &str) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);
    // aes-gcm appends the tag; the envelope puts it before the ciphertext.
    let mut body = cipher
        .encrypt(
            &iv,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .expect("AES-GCM encryption does not fail for in-memory buffers");
    let tag = body.split_off(body.len() - TAG_BYTES);
    let mut sealed = Vec::with_capacity(1 + IV_BYTES + TAG_BYTES + body.len());
    sealed.push(VERSION);
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&tag);
    sealed.extend_from_slice(&body);
    sealed
}

pub fn open(key: &[u8; 32], sealed: &[u8], aad: &str) -> Result<Vec<u8>> {
    if sealed.len() < 1 + IV_BYTES + TAG_BYTES || sealed[0] != VERSION {
        bail!("Unsupported sealed value");
    }
    let iv = &sealed[1..1 + IV_BYTES];
    let tag = &sealed[1 + IV_BYTES..1 + IV_BYTES + TAG_BYTES];
    let mut combined = sealed[1 + IV_BYTES + TAG_BYTES..].to_vec();
    combined.extend_from_slice(tag);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &combined,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Unsupported state or unable to authenticate data"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Produced by envelope.ts: root = 32 × 0x07, purpose signing-keys, aad "kid-123".
    const ROOT: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    const DERIVED: &str = "1342ec04ca763be87c32d3484119c59457f4068ab981448bf8a1f3af895b7ab6";
    const SEALED: &str =
        "014a6dd9f6da768c2b1d80951febb7dcbd982109eec885aee5eaf7bf051a0d1a94ed243aac47f36167a21b610e0ff0362717";

    #[test]
    fn derives_the_same_subkey_as_node() {
        let key = derive_key(&parse_root_key(ROOT).unwrap(), Purpose::SigningKeys);
        assert_eq!(key.to_vec(), hex(DERIVED));
    }

    #[test]
    fn opens_what_node_sealed() {
        let key = derive_key(&parse_root_key(ROOT).unwrap(), Purpose::SigningKeys);
        assert_eq!(
            open(&key, &hex(SEALED), "kid-123").unwrap(),
            br#"{"hello":"handstamp"}"#
        );
    }

    #[test]
    fn aad_binds_the_ciphertext_to_its_row() {
        let key = derive_key(&parse_root_key(ROOT).unwrap(), Purpose::SigningKeys);
        assert!(open(&key, &hex(SEALED), "kid-456").is_err());
        let sealed = seal(&key, b"secret", "row-a");
        assert_eq!(open(&key, &sealed, "row-a").unwrap(), b"secret");
        assert!(open(&key, &sealed, "row-b").is_err());
    }

    #[test]
    fn rejects_short_keys() {
        assert!(parse_root_key("c2hvcnQ=").is_err());
    }
}
