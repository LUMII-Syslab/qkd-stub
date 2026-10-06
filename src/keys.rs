use base64::{Engine, engine::general_purpose::STANDARD};
use ring::hkdf;
use serde::Serialize;
use uuid::Uuid;

pub const MAX_BITS: u32 = 65_536;
pub const MAX_COUNT: usize = 128;
const DOMAIN: &[u8] = b"qkd-stub:key:v6\0";

const CHECK_DOMAIN: &[u8] = b"qkd-stub:id-check:v6\0";

/// Extracted shared secret. Intentionally does not implement Debug or Serialize.
#[derive(Clone)]
pub struct Psk(hkdf::Prk);

impl Psk {
    pub fn new(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("PSK file must contain exactly 32 raw bytes (not hex or Base64)");
        }
        Ok(Self(
            hkdf::Salt::new(hkdf::HKDF_SHA512, b"qkd-stub:psk\0").extract(bytes),
        ))
    }
}

struct KeyLength(usize);
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

const NOT_FOUND: &str = "one or more keys specified are not found on KME";

#[derive(Debug, Serialize)]
pub struct Key {
    #[serde(rename = "key_ID")]
    pub key_id: String,
    pub key: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parties {
    pub master: u16,
    pub slave: u16,
}
#[derive(Debug)]
pub enum AccessError {
    Invalid(String),
    Unauthorized,
}

pub fn generate(bits: u32, psk: &Psk) -> Result<Key, String> {
    generate_inner(bits, None, psk)
}
pub fn generate_bound(bits: u32, parties: Parties, psk: &Psk) -> Result<Key, String> {
    if parties.master == 0 || parties.slave == 0 {
        return Err("SAE codes must be nonzero".into());
    }
    generate_inner(bits, Some(parties), psk)
}
fn generate_inner(bits: u32, parties: Option<Parties>, psk: &Psk) -> Result<Key, String> {
    if !(8..=MAX_BITS).contains(&bits) || !bits.is_multiple_of(8) {
        return Err("invalid key size".into());
    }
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("random ID generation failed: {e}"))?;
    bytes[0..2].copy_from_slice(&((bits / 8) as u16).to_be_bytes());
    let p = parties.unwrap_or(Parties {
        master: 0,
        slave: 0,
    });
    bytes[2..4].copy_from_slice(&p.master.to_be_bytes());
    bytes[4..6].copy_from_slice(&p.slave.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes[15] = check_byte(&bytes[..15], psk);
    Ok(material(Uuid::from_bytes(bytes), (bits / 8) as usize, psk))
}

fn parse(id: &str, psk: &Psk) -> Result<(Uuid, usize, Parties), String> {
    let uuid = Uuid::parse_str(id).map_err(|_| "invalid key ID")?;
    if id.len() != 36 || !uuid.hyphenated().to_string().eq_ignore_ascii_case(id) {
        return Err("invalid key ID".into());
    }
    let bytes = uuid.as_bytes();
    let size = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes[6] >> 4 != 8 || bytes[8] >> 6 != 2 || !(1..=MAX_BITS as usize / 8).contains(&size) {
        return Err(NOT_FOUND.into());
    }
    if bytes[15] != check_byte(&bytes[..15], psk) {
        return Err("key ID checksum mismatch (wrong PSK or damaged ID)".into());
    }
    let parties = Parties {
        master: u16::from_be_bytes([bytes[2], bytes[3]]),
        slave: u16::from_be_bytes([bytes[4], bytes[5]]),
    };
    Ok((uuid, size, parties))
}
// One-byte configuration check only: wrong PSKs can pass with probability 1/256.
fn check_byte(input: &[u8], psk: &Psk) -> u8 {
    let mut out = [0];
    expand(CHECK_DOMAIN, input, psk, &mut out);
    out[0]
}
fn expand(domain: &[u8], input: &[u8], psk: &Psk, output: &mut [u8]) {
    let info: &[&[u8]] = &[domain, input];
    // SHA-512 supports the full 8192-byte API limit; HKDF-SHA256 stops at 8160.
    psk.0
        .expand(info, KeyLength(output.len()))
        .expect("validated key size fits HKDF-SHA512")
        .fill(output)
        .expect("output buffer matches requested HKDF length");
}
fn material(uuid: Uuid, size: usize, psk: &Psk) -> Key {
    let mut key = vec![0; size];
    expand(DOMAIN, uuid.as_bytes(), psk, &mut key);
    Key {
        key_id: uuid.to_string(),
        key: STANDARD.encode(key),
    }
}
pub fn derive(id: &str, psk: &Psk) -> Result<Key, String> {
    let (uuid, size, _) = parse(id, psk)?;
    Ok(material(uuid, size, psk))
}
pub fn derive_bound(id: &str, expected: Parties, psk: &Psk) -> Result<Key, AccessError> {
    let (uuid, size, parties) = parse(id, psk).map_err(AccessError::Invalid)?;
    if expected.master == 0 || expected.slave == 0 || parties != expected {
        return Err(AccessError::Unauthorized);
    }
    Ok(material(uuid, size, psk))
}
