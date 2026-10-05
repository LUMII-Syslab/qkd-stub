//! Certificate selectors and the shared SAE code registry for opt-in authorization.
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use x509_parser::{extensions::GeneralName, prelude::*};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(
    tag = "field",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Selector {
    SubjectDn(String),
    SanDns(String),
    SanUri(String),
    SanEmail(String),
    SanIp(String),
}
impl Selector {
    fn normalize(&self) -> Result<Self, String> {
        let value = match self {
            Self::SubjectDn(v)
            | Self::SanDns(v)
            | Self::SanUri(v)
            | Self::SanEmail(v)
            | Self::SanIp(v) => v,
        };
        if value.is_empty() {
            return Err("certificate selector must not be empty".into());
        }
        Ok(match self {
            Self::SanDns(v) => Self::SanDns(v.to_ascii_lowercase()),
            Self::SanIp(v) => Self::SanIp(
                v.parse::<IpAddr>()
                    .map_err(|_| "invalid SAN IP selector")?
                    .to_string(),
            ),
            other => other.clone(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    saes: Vec<Sae>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sae {
    id: String,
    code: u16,
    #[serde(default)]
    identities: Vec<Selector>,
}

#[derive(Clone, Debug)]
pub struct Registry {
    by_id: HashMap<String, u16>,
    by_code: HashMap<u16, String>,
    identities: HashMap<Selector, u16>,
}
impl Registry {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let config: RegistryFile =
            serde_json::from_str(json).map_err(|e| format!("invalid SAE mapping: {e}"))?;
        if config.saes.is_empty() {
            return Err("SAE mapping must contain at least one SAE".into());
        }
        let mut registry = Self {
            by_id: HashMap::new(),
            by_code: HashMap::new(),
            identities: HashMap::new(),
        };
        for sae in config.saes {
            if sae.id.trim().is_empty() || sae.code == 0 {
                return Err("SAE IDs must be nonempty and codes must be 1–65535".into());
            }
            if registry.by_id.insert(sae.id.clone(), sae.code).is_some() {
                return Err(format!("duplicate SAE ID: {}", sae.id));
            }
            if registry.by_code.insert(sae.code, sae.id.clone()).is_some() {
                return Err(format!("duplicate SAE code: {}", sae.code));
            }
            for identity in sae.identities {
                if registry
                    .identities
                    .insert(identity.normalize()?, sae.code)
                    .is_some()
                {
                    return Err(
                        "duplicate certificate selector (including normalized DNS/IP values)"
                            .into(),
                    );
                }
            }
        }
        Ok(registry)
    }
    pub fn code(&self, id: &str) -> Option<u16> {
        self.by_id.get(id).copied()
    }
    pub fn id(&self, code: u16) -> Option<&str> {
        self.by_code.get(&code).map(String::as_str)
    }
    pub fn identify(&self, certificate: &[u8]) -> Result<u16, String> {
        let selectors = certificate_selectors(certificate)?;
        let matches: HashSet<u16> = selectors
            .iter()
            .filter_map(|s| self.identities.get(s).copied())
            .collect();
        if matches.len() != 1 {
            return Err("certificate must map unambiguously to exactly one SAE".into());
        }
        Ok(*matches.iter().next().unwrap())
    }
}

/// Exact RFC4514-style rendering in reverse RDN order; escape values to avoid
/// conflating separators inside an attribute with actual DN structure.
fn subject_dn(name: &X509Name<'_>) -> Result<String, String> {
    let mut rdns = Vec::new();
    for rdn in name.iter_rdn() {
        let mut attrs = Vec::new();
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_id_string();
            let label = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.9" => "STREET",
                "0.9.2342.19200300.100.1.25" => "DC",
                "0.9.2342.19200300.100.1.1" => "UID",
                _ => &oid,
            };
            let value = attr
                .as_str()
                .map_err(|_| "DN contains an unsupported non-UTF8 attribute; use a SAN selector")?;
            let chars: Vec<_> = value.chars().collect();
            let mut escaped = String::new();
            for (i, c) in chars.iter().copied().enumerate() {
                if c.is_control() {
                    for byte in c.to_string().as_bytes() {
                        escaped.push_str(&format!("\\{byte:02X}"));
                    }
                } else {
                    if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=')
                        || (i == 0 && (c == ' ' || c == '#'))
                        || (i + 1 == chars.len() && c == ' ')
                    {
                        escaped.push('\\');
                    }
                    escaped.push(c);
                }
            }
            attrs.push(format!("{label}={escaped}"));
        }
        // An RDN is an unordered set. Use a stable order for multivalued RDNs.
        attrs.sort();
        rdns.push(attrs.join("+"));
    }
    rdns.reverse();
    Ok(rdns.join(","))
}

pub fn certificate_selectors(der: &[u8]) -> Result<Vec<Selector>, String> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("invalid X.509 certificate: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing certificate data".into());
    }
    let mut selectors = Vec::new();
    // Unsupported DN encodings do not prevent an otherwise valid SAN mapping.
    if let Ok(dn) = subject_dn(cert.subject()) {
        selectors.push(Selector::SubjectDn(dn));
    }
    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|_| "invalid or duplicate SAN extension")?
    {
        for name in &san.value.general_names {
            let selector = match name {
                GeneralName::DNSName(v) => Some(Selector::SanDns(v.to_ascii_lowercase())),
                GeneralName::URI(v) => Some(Selector::SanUri(v.to_string())),
                GeneralName::RFC822Name(v) => Some(Selector::SanEmail(v.to_string())),
                GeneralName::IPAddress(bytes) => {
                    let ip = match bytes.len() {
                        4 => IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap()),
                        16 => IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap()),
                        _ => return Err("invalid SAN IP address".into()),
                    };
                    Some(Selector::SanIp(ip.to_string()))
                }
                _ => None,
            };
            if let Some(selector) = selector {
                selectors.push(selector);
            }
        }
    }
    Ok(selectors)
}

/// Inserted by the TLS acceptor, never obtained from HTTP headers.
#[derive(Clone, Copy, Debug)]
pub struct PeerIdentity(pub Option<u16>);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_ambiguous_or_invalid_registry() {
        for json in [
            r#"{"saes":[]}"#,
            r#"{"saes":[{"id":"A","code":0}]}"#,
            r#"{"saes":[{"id":"A","code":1},{"id":"B","code":1}]}"#,
            r#"{"saes":[{"id":"A","code":1},{"id":"A","code":2}]}"#,
            r#"{"saes":[{"id":"A","code":1,"identities":[{"field":"san_dns","value":"A.local"}]},{"id":"B","code":2,"identities":[{"field":"san_dns","value":"a.LOCAL"}]}]}"#,
            r#"{"saes":[{"id":"A","code":1,"identities":[{"field":"san_ip","value":"no"}]}]}"#,
            r#"{"saes":[{"id":"A","code":1,"typo":true}]}"#,
        ] {
            assert!(Registry::from_json(json).is_err(), "{json}");
        }
        let r =
            Registry::from_json(r#"{"saes":[{"id":"A","code":1},{"id":"B","code":2}]}"#).unwrap();
        assert_eq!(r.code("A"), Some(1));
        assert_eq!(r.id(2), Some("B"));
        assert_eq!(r.code("unknown"), None);
    }
}
