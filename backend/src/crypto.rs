//! Secrets at rest and the small primitives around them. The envelope is byte-for-byte what the
//! Node server wrote: HKDF-SHA256 subkeys per purpose, AES-256-GCM sealed as
//! version (1) · iv (12) · tag (16) · ciphertext, with AAD binding a ciphertext to its row.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result, bail};
use aws_lc_rs::{hmac, rand::SecureRandom};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;
const IV_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// One subkey per kind of secret, so a leaked ciphertext of one kind can never be opened as another.
#[derive(Clone, Copy)]
pub enum Purpose {
    ClientSecrets,
    SigningKeys,
    ConsoleClient,
    UpstreamSecrets,
    StateCookies,
    Csrf,
}

impl Purpose {
    fn info(self) -> &'static [u8] {
        match self {
            Purpose::ClientSecrets => b"client-secrets",
            Purpose::SigningKeys => b"signing-keys",
            Purpose::ConsoleClient => b"console-client",
            Purpose::UpstreamSecrets => b"upstream-secrets",
            Purpose::StateCookies => b"state-cookies",
            Purpose::Csrf => b"csrf",
        }
    }
}

pub fn parse_root_key(value: &str) -> Result<Vec<u8>> {
    let key = STANDARD
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
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let iv = random_bytes::<IV_BYTES>();
    // aes-gcm appends the tag; the envelope puts it before the ciphertext.
    let mut body = cipher
        .encrypt(
            &Nonce::from(iv),
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
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
        .decrypt(
            &Nonce::try_from(iv).expect("the IV is IV_BYTES long"),
            Payload {
                msg: &combined,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Unsupported state or unable to authenticate data"))
}

pub fn open_string(key: &[u8; 32], sealed: &[u8], aad: &str) -> Result<String> {
    Ok(String::from_utf8(open(key, sealed, aad)?)?)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("the system RNG is available");
    out
}

/// base64url, no padding: what randomBytes(n).toString('base64url') produced.
pub fn random_token(bytes: usize) -> String {
    let mut out = vec![0u8; bytes];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut out)
        .expect("the system RNG is available");
    b64url(&out)
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()
}

pub fn sha256(value: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(value.as_ref()).into()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// HMAC-SHA256 of a binding (interaction uid, console session), base64url: the CSRF token (S5).
pub fn csrf_token(key: &[u8; 32], binding: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    b64url(hmac::sign(&key, binding.as_bytes()).as_ref())
}

pub fn csrf_valid(key: &[u8; 32], binding: &str, presented: Option<&str>) -> bool {
    presented.is_some_and(|token| constant_time_eq(csrf_token(key, binding).as_bytes(), token.as_bytes()))
}

// Crockford base32: no I, L, O or U, so codes read aloud or retyped from logs survive.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The one-time setup code printed at first boot: HS-XXXXX-XXXXX-XXXXX-XXXXX (100 bits).
pub fn new_setup_code() -> String {
    let chars: Vec<char> = random_bytes::<20>()
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    let groups: Vec<String> = chars.chunks(5).map(|c| c.iter().collect()).collect();
    format!("HS-{}", groups.join("-"))
}

/// Forgiving about case, spaces, dashes and look-alike letters; strict about everything else.
pub fn normalize_setup_code(input: &str) -> String {
    let upper: String = input
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let stripped = upper.strip_prefix("HS").unwrap_or(&upper);
    stripped.replace('O', "0").replace(['I', 'L'], "1")
}

pub fn hash_setup_code(input: &str) -> [u8; 32] {
    sha256(format!("setup:{}", normalize_setup_code(input)))
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

    // Produced by the Node envelope: root = 32 × 0x07, purpose signing-keys, aad "kid-123".
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

    #[test]
    fn setup_codes_are_forgiving_but_exact() {
        let code = new_setup_code();
        assert!(
            regex::Regex::new(r"^HS-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$")
                .unwrap()
                .is_match(&code)
        );
        assert_eq!(
            hash_setup_code(&code),
            hash_setup_code(&code.to_lowercase().replace('-', " "))
        );
        assert_eq!(normalize_setup_code("hs-0o1il"), "00111");
        assert_ne!(hash_setup_code("HS-00000-00000-00000-00000"), hash_setup_code(&code));
    }

    #[test]
    fn csrf_tokens_are_bound() {
        let key = [3u8; 32];
        let token = csrf_token(&key, "interaction:a");
        assert!(csrf_valid(&key, "interaction:a", Some(&token)));
        assert!(!csrf_valid(&key, "interaction:b", Some(&token)));
        assert!(!csrf_valid(&key, "interaction:a", None));
    }
}
