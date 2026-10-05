use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use uuid::Uuid;

pub const MAX_BITS: u32 = 65_536;
pub const MAX_COUNT: usize = 128;
const DOMAIN: &[u8] = b"qkd-stub:v1\0";
const BOUND_DOMAIN: &[u8] = b"qkd-stub:v2\0";
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

pub fn generate(bits: u32) -> Result<Key, String> {
    generate_inner(bits, None)
}
pub fn generate_bound(bits: u32, parties: Parties) -> Result<Key, String> {
    if parties.master == 0 || parties.slave == 0 {
        return Err("SAE codes must be nonzero".into());
    }
    generate_inner(bits, Some(parties))
}
fn generate_inner(bits: u32, parties: Option<Parties>) -> Result<Key, String> {
    if !(8..=MAX_BITS).contains(&bits) || !bits.is_multiple_of(8) {
        return Err("invalid key size".into());
    }
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("random ID generation failed: {e}"))?;
    bytes[0..2].copy_from_slice(if parties.is_some() { b"QA" } else { b"QK" });
    bytes[2..4].copy_from_slice(&((bits / 8) as u16).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    if let Some(p) = parties {
        bytes[4..6].copy_from_slice(&p.master.to_be_bytes());
        bytes[10..12].copy_from_slice(&p.slave.to_be_bytes());
    }
    Ok(material(
        Uuid::from_bytes(bytes),
        (bits / 8) as usize,
        parties.is_some(),
    ))
}

fn parse(id: &str) -> Result<(Uuid, usize, Option<Parties>), String> {
    let uuid = Uuid::parse_str(id).map_err(|_| "invalid key ID")?;
    if id.len() != 36 || !uuid.hyphenated().to_string().eq_ignore_ascii_case(id) {
        return Err("invalid key ID".into());
    }
    let bytes = uuid.as_bytes();
    let size = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if bytes[6] >> 4 != 8 || bytes[8] >> 6 != 2 || !(1..=MAX_BITS as usize / 8).contains(&size) {
        return Err(NOT_FOUND.into());
    }
    let parties = match &bytes[0..2] {
        b"QK" => None,
        b"QA" => {
            let p = Parties {
                master: u16::from_be_bytes([bytes[4], bytes[5]]),
                slave: u16::from_be_bytes([bytes[10], bytes[11]]),
            };
            if p.master == 0 || p.slave == 0 {
                return Err(NOT_FOUND.into());
            }
            Some(p)
        }
        _ => return Err(NOT_FOUND.into()),
    };
    Ok((uuid, size, parties))
}
fn material(uuid: Uuid, size: usize, bound: bool) -> Key {
    let mut hash = Shake256::default();
    hash.update(if bound { BOUND_DOMAIN } else { DOMAIN });
    hash.update(uuid.as_bytes());
    let mut key = vec![0; size];
    hash.finalize_xof().read(&mut key);
    Key {
        key_id: uuid.to_string(),
        key: STANDARD.encode(key),
    }
}
pub fn derive(id: &str) -> Result<Key, String> {
    let (uuid, size, parties) = parse(id)?;
    if parties.is_some() {
        return Err(NOT_FOUND.into());
    }
    Ok(material(uuid, size, false))
}
pub fn derive_bound(id: &str, expected: Parties) -> Result<Key, AccessError> {
    let (uuid, size, parties) = parse(id).map_err(AccessError::Invalid)?;
    if parties != Some(expected) {
        return Err(AccessError::Unauthorized);
    }
    Ok(material(uuid, size, true))
}
