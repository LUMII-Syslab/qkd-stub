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

#[derive(Debug, Serialize)]
pub struct Key {
    #[serde(rename = "key_ID")]
    pub key_id: String,
    pub key: String,
}

pub fn generate(bits: u32) -> Result<Key, String> {
    if !(8..=MAX_BITS).contains(&bits) || !bits.is_multiple_of(8) {
        return Err("invalid key size".into());
    }
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("random ID generation failed: {e}"))?;
    bytes[0..2].copy_from_slice(b"QK");
    bytes[2..4].copy_from_slice(&((bits / 8) as u16).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    derive(&Uuid::from_bytes(bytes).to_string())
}

pub fn derive(id: &str) -> Result<Key, String> {
    let uuid = Uuid::parse_str(id).map_err(|_| "invalid key ID")?;
    // Accept only the standard hyphenated UUID wire format (case-insensitive).
    if id.len() != 36 || !uuid.hyphenated().to_string().eq_ignore_ascii_case(id) {
        return Err("invalid key ID".into());
    }
    let bytes = uuid.as_bytes();
    let size = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if &bytes[0..2] != b"QK"
        || bytes[6] >> 4 != 8
        || bytes[8] >> 6 != 2
        || !(1..=MAX_BITS as usize / 8).contains(&size)
    {
        return Err("one or more keys specified are not found on KME".into());
    }
    let mut hash = Shake256::default();
    hash.update(DOMAIN);
    hash.update(bytes);
    let mut key = vec![0; size];
    hash.finalize_xof().read(&mut key);
    Ok(Key {
        key_id: uuid.to_string(),
        key: STANDARD.encode(key),
    })
}
