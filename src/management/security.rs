use axum::http::HeaderMap;
use std::{collections::HashSet, net::IpAddr};
use url::Url;

#[derive(Clone)]
pub struct SecurityPolicy {
    hosts: HashSet<String>,
    trusted: HashSet<String>,
    allow_any: bool,
}
fn origin(value: &str) -> Option<String> {
    if value.contains(['\\', '@', '?', '#']) || value.trim() != value {
        return None;
    }
    let u = Url::parse(value).ok()?;
    if !matches!(u.scheme(), "http" | "https") || u.path() != "/" || u.host_str().is_none() {
        return None;
    }
    let authority = value.split_once("://")?.1;
    if authority.contains('/') {
        return None;
    }
    // URL parsers accept legacy octal/short IPv4; the management boundary does not.
    let raw = if authority.starts_with('[') {
        authority.split(']').next()?.trim_start_matches('[')
    } else {
        authority.split(':').next()?
    };
    let parsed = u.host_str()?.trim_start_matches('[').trim_end_matches(']');
    if let Ok(IpAddr::V4(ip)) = parsed.parse::<IpAddr>() {
        if raw != ip.to_string() {
            return None;
        }
    }
    Some(u.origin().ascii_serialization())
}
impl SecurityPolicy {
    pub fn new(
        hosts: impl IntoIterator<Item = String>,
        trusted: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<Self> {
        let hosts = hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect();
        let trusted = trusted.into_iter().collect::<Vec<_>>();
        let allow_any = trusted.iter().any(|s| s == "*");
        let trusted = trusted
            .into_iter()
            .filter(|s| s != "*")
            .map(|s| origin(&s).ok_or_else(|| anyhow::anyhow!("invalid trusted origin")))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            hosts,
            trusted,
            allow_any,
        })
    }
    pub fn allows(&self, headers: &HeaderMap, scheme: &str, management: bool) -> bool {
        if headers.get_all("host").iter().count() != 1
            || headers.get_all("origin").iter().count() > 1
        {
            return false;
        }
        let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) else {
            return false;
        };
        if host.contains(['/', '\\', '@', '?', '#']) {
            return false;
        }
        let Some(target) = origin(&format!("{scheme}://{host}")) else {
            return false;
        };
        let Ok(url) = Url::parse(&target) else {
            return false;
        };
        let h = url
            .host_str()
            .unwrap_or("")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        let loopback = h == "localhost" || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback && !self.hosts.contains(&h) {
            return false;
        }
        if !management {
            return true;
        }
        match headers.get("origin") {
            None => true,
            Some(value) => value
                .to_str()
                .ok()
                .and_then(origin)
                .is_some_and(|o| self.allow_any || o == target || self.trusted.contains(&o)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_dns_rebinding_and_ambiguous_origins() {
        let p = SecurityPolicy::new(["192.168.1.2".into()], []).unwrap();
        let mut h = HeaderMap::new();
        h.insert("host", "localhost:12043".parse().unwrap());
        assert!(p.allows(&h, "http", true));
        h.insert("origin", "https://attacker.example".parse().unwrap());
        assert!(!p.allows(&h, "http", true));
        h.insert("origin", "http://localhost:12043".parse().unwrap());
        assert!(p.allows(&h, "http", true));
        h.append("host", "evil.example".parse().unwrap());
        assert!(!p.allows(&h, "http", true));
        assert!(origin("http://127.1:12043").is_none());
        assert!(origin("http://0177.0.0.1").is_none());
        assert!(origin("http://user@localhost").is_none());
        assert!(origin("http://localhost/a").is_none());
        assert!(origin("http://localhost/").is_none());
    }
}
