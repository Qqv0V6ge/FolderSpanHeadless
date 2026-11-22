use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: u32 = 1;
pub const BODY_LIMIT: usize = 1024 * 1024;
pub const HEADER_LIMIT: usize = 32 * 1024;
pub const WIRE_LIMIT: usize = 4 + HEADER_LIMIT + BODY_LIMIT;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct Header {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: i64,
    pub method: String,
    pub path: String,
    pub content_type: String,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub handle: String,
    pub event_type: String,
    pub requires_reply: bool,
    pub token: String,
    pub version: u32,
}
impl Default for Header {
    fn default() -> Self {
        Self {
            kind: String::new(),
            id: 0,
            method: String::new(),
            path: String::new(),
            content_type: String::new(),
            status: 0,
            headers: BTreeMap::new(),
            handle: String::new(),
            event_type: String::new(),
            requires_reply: false,
            token: String::new(),
            version: VERSION,
        }
    }
}
#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub body: Vec<u8>,
}
impl Packet {
    pub fn new(kind: &str) -> Self {
        Self {
            header: Header {
                kind: kind.into(),
                ..Header::default()
            },
            body: Vec::new(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let header = serde_json::to_vec(&self.header)?;
        ensure!(
            (1..=HEADER_LIMIT).contains(&header.len()) && self.body.len() <= BODY_LIMIT,
            "management message too large"
        );
        let mut bytes = Vec::with_capacity(4 + header.len() + self.body.len());
        bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
        bytes.extend(header);
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (5..=WIRE_LIMIT).contains(&bytes.len()),
            "invalid management message size"
        );
        let len = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
        ensure!(
            (1..=HEADER_LIMIT).contains(&len)
                && len <= bytes.len() - 4
                && bytes.len() - 4 - len <= BODY_LIMIT,
            "invalid management header size"
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes[4..4 + len])?;
        ensure!(
            value.get("type").and_then(|v| v.as_str()).is_some(),
            "missing message type"
        );
        Ok(Self {
            header: serde_json::from_value(value)?,
            body: bytes[4 + len..].to_vec(),
        })
    }
}
pub fn is_body_route(method: &str, raw: &str) -> bool {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let path = path.strip_prefix("/api/web-ui/platform").unwrap_or("");
    match path {
        "/files/content" | "/devices/write" => true,
        "/files/append" => method == "POST",
        "/listeners/body" => matches!(method, "GET" | "PUT"),
        "/networks/downloads" | "/http/download" | "/devices/read" => method == "GET",
        "/networks/uploads" | "/http/upload" | "/compression" => matches!(method, "PUT" | "GET"),
        "/networks/advanced/upload-chunk" => method == "PUT",
        "/devices/transport" => self::query(query)
            .get("operation")
            .is_some_and(|v| matches!(v.as_str(), "body" | "data")),
        _ => false,
    }
}
pub fn is_command_route(method: &str, raw: &str) -> bool {
    raw.starts_with("/api/web-ui/platform/")
        && !is_body_route(method, raw)
        && !raw.contains('#')
        && !raw.split('?').next().unwrap_or("").contains(['\\', '%'])
        && !raw
            .split('?')
            .next()
            .unwrap_or("")
            .split('/')
            .any(|p| matches!(p, "." | ".."))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kotlin_defaults_and_binary_roundtrip() {
        let mut bytes = Vec::from(15u32.to_be_bytes());
        bytes.extend_from_slice(br#"{"type":"auth"}"#);
        // Header length must be byte-exact.
        let len = (bytes.len() - 4) as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        let p = Packet::decode(&bytes).unwrap();
        assert_eq!(p.header.version, 1);
        assert_eq!(p.header.id, 0);
        let mut p = p;
        p.body = vec![0, 255, 128];
        assert_eq!(Packet::decode(&p.encode().unwrap()).unwrap().body, p.body);
    }
    #[test]
    fn malformed_and_over_limit_are_rejected() {
        for b in [vec![], vec![0; 4], vec![255; 8], vec![0, 0, 0, 1, b'{']] {
            assert!(Packet::decode(&b).is_err());
        }
        let mut p = Packet::new("request");
        p.body = vec![0; BODY_LIMIT + 1];
        assert!(p.encode().is_err());
        assert!(!is_command_route("POST", "/api/web-ui/platform/../files"));
        assert!(!is_command_route(
            "GET",
            "/api/web-ui/platform/files/content?path=x"
        ));
    }
}

// Kotlin queryParameters[name] uses the first value for duplicate parameters.
pub fn query(raw: &str) -> std::collections::HashMap<String, String> {
    let mut values = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        values
            .entry(key.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    values
}
#[cfg(test)]
mod query_tests {
    #[test]
    fn duplicate_query_uses_first_and_decodes_once() {
        let q = super::query("handle=one&handle=two&path=a%252Fb%20%2B");
        assert_eq!(q["handle"], "one");
        assert_eq!(q["path"], "a%2Fb +");
    }
}
