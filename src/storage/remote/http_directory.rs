use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::Entry,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use reqwest::{Client, header};
use scraper::{Html, Selector};
use std::{collections::HashSet, time::Duration};
use tokio::sync::mpsc;
use url::Url;

#[derive(Clone)]
pub struct HttpDirectory {
    root: Url,
    segments: Vec<String>,
    authorization: Option<header::HeaderValue>,
    client: Client,
}
pub(crate) fn segment(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && !matches!(trimmed, "." | "..")
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control)
}
pub(crate) fn segments(url: &Url) -> Option<Vec<String>> {
    let path = url.path().trim_matches('/');
    if path.is_empty() {
        return Some(vec![]);
    }
    path.split('/')
        .map(|part| {
            let decoded = percent_encoding::percent_decode_str(part)
                .decode_utf8()
                .ok()?
                .into_owned();
            segment(&decoded).then_some(decoded)
        })
        .collect()
}
pub(crate) fn raw_path_safe(value: &str) -> bool {
    let path = value
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map(|(_, path)| path).unwrap_or(""))
        .unwrap_or(value);
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_matches('/');
    path.is_empty()
        || path.split('/').all(|part| {
            percent_encoding::percent_decode_str(part)
                .decode_utf8()
                .is_ok_and(|s| segment(&s))
        })
}
pub(crate) fn client() -> Result<Client> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .http1_only()
        .build()?)
}
fn failure(message: &'static str) -> anyhow::Error {
    ResourceUnavailable(message).into()
}
pub(crate) fn root_url(host: &str) -> Result<Url> {
    ensure!(
        !host.chars().any(char::is_control) && !host.contains('\\') && raw_path_safe(host),
        "invalid HTTP directory root"
    );
    let root = Url::parse(host)?;
    ensure!(
        matches!(root.scheme(), "http" | "https")
            && root.host_str().is_some()
            && root.username().is_empty()
            && root.password().is_none_or(str::is_empty)
            && root.query().is_none_or(str::is_empty)
            && root.fragment().is_none_or(str::is_empty),
        "invalid HTTP directory root"
    );
    Ok(root)
}
impl HttpDirectory {
    pub fn new(host: &str, username: &str, password: &str) -> Result<Self> {
        let root = root_url(host)?;
        let segments = segments(&root).context("invalid directory root")?;
        let authorization = if username.is_empty() && password.is_empty() {
            None
        } else {
            Some(header::HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            ))?)
        };
        Ok(Self {
            root,
            segments,
            authorization,
            client: client()?,
        })
    }
    pub fn transfer(&self) -> Result<Self> {
        let mut copy = self.clone();
        copy.client = client()?;
        Ok(copy)
    }
    fn url(&self, path: &str, directory: bool) -> Result<Url> {
        let path = path.trim_matches('/');
        let parts = if path.is_empty() {
            vec![]
        } else {
            path.split('/').collect::<Vec<_>>()
        };
        ensure!(
            parts.iter().all(|v| segment(v)),
            "invalid remote directory path"
        );
        let mut url = self.root.clone();
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| failure("invalid HTTP directory root"))?;
            segments.clear();
            segments.extend(self.segments.iter().map(String::as_str));
            segments.extend(parts);
            if directory {
                segments.push("");
            }
        }
        Ok(url)
    }
    fn allowed(&self, target: &Url) -> bool {
        target.scheme() == self.root.scheme()
            && target.host_str() == self.root.host_str()
            && target.port_or_known_default() == self.root.port_or_known_default()
            && target.username().is_empty()
            && target.password().is_none_or(str::is_empty)
            && target.query().is_none_or(str::is_empty)
            && target.fragment().is_none_or(str::is_empty)
            && segments(target).is_some_and(|parts| parts.starts_with(&self.segments))
    }
    fn request(&self, url: Url) -> reqwest::RequestBuilder {
        let mut request = self.client.get(url);
        if let Some(authorization) = &self.authorization {
            request = request.header(header::AUTHORIZATION, authorization.clone());
        }
        request
    }
    pub fn parse(&self, html: &str, current: &Url) -> Result<Vec<Entry>> {
        ensure!(self.allowed(current), "directory leaves configured root");
        let parent = segments(current).context("invalid directory path")?;
        let document = Html::parse_document(html);
        let anchor = Selector::parse("a[href]").unwrap();
        let base = Selector::parse("base[href]").unwrap();
        let base = document
            .select(&base)
            .next()
            .and_then(|e| current.join(e.value().attr("href")?).ok())
            .unwrap_or_else(|| current.clone());
        let mut seen = HashSet::new();
        let mut entries = vec![];
        for (index, link) in document.select(&anchor).enumerate() {
            ensure!(
                index < 100_000,
                ResourceUnavailable("too many directory links")
            );
            let href = link.value().attr("href").unwrap();
            if href.trim().is_empty()
                || href.chars().any(char::is_control)
                || href.contains('\\')
                || !raw_path_safe(href)
            {
                continue;
            }
            let Ok(target) = base.join(href) else {
                continue;
            };
            if !self.allowed(&target) {
                continue;
            }
            let Some(parts) = segments(&target) else {
                continue;
            };
            if parts.len() != parent.len() + 1 || !parts.starts_with(&parent) {
                continue;
            }
            let name = parts.last().unwrap().clone();
            let path = format!("/{}", parts[self.segments.len()..].join("/"));
            if seen.insert(path.clone()) {
                entries.push(Entry {
                    name: name.clone(),
                    path,
                    is_directory: target.path().ends_with('/'),
                    size: -1,
                    created_date: 0,
                    updated_date: 0,
                    is_hidden: name.starts_with('.'),
                    is_symbolic_link: false,
                    is_symbolic_link_known: true,
                    reference: None,
                });
            }
        }
        Ok(entries)
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let current = self.url(path, true)?;
        let response = self
            .request(current.clone())
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(
            response.status().is_success(),
            ResourceUnavailable("HTTP directory listing failed")
        );
        let media = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap()
            .trim();
        ensure!(
            media.eq_ignore_ascii_case("text/html")
                || media.eq_ignore_ascii_case("application/xhtml+xml"),
            ResourceUnavailable("URL did not return an HTML directory")
        );
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(part) = stream.next().await {
            let part = part.map_err(|_| PlatformFailure)?;
            ensure!(
                part.len() <= 8 * 1024 * 1024 - bytes.len(),
                ResourceUnavailable("storage response exceeds size limit")
            );
            bytes.extend(part);
        }
        let html = String::from_utf8_lossy(&bytes).into_owned();
        let owner = self.clone();
        tokio::task::spawn_blocking(move || owner.parse(&html, &current)).await?
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<crate::storage::remote::DownloadPart>,
    ) -> Result<()> {
        let mut current = self.url(path, false)?;
        let mut visited = HashSet::new();
        for _ in 0..6 {
            ensure!(
                visited.insert(current.clone()),
                ResourceUnavailable("storage redirect cycle")
            );
            let response = self
                .request(current.clone())
                .header(header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|_| PlatformFailure)?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .context(ResourceUnavailable("storage redirect has no destination"))?
                    .to_str()?;
                ensure!(
                    raw_path_safe(location),
                    ResourceUnavailable("storage redirect leaves allowed root")
                );
                let next = current.join(location)?;
                ensure!(
                    self.allowed(&next),
                    ResourceUnavailable("storage redirect leaves allowed origin or root")
                );
                current = next;
                continue;
            }
            ensure!(
                response.status().is_success(),
                ResourceUnavailable("storage download failed")
            );
            let expected = response
                .content_length()
                .map(i64::try_from)
                .transpose()?
                .unwrap_or(if size >= 0 { size } else { -1 });
            ensure!(
                size < 0 || expected < 0 || size == expected,
                ResourceUnavailable("storage file size changed")
            );
            let mut input = response.bytes_stream();
            let mut received = 0u64;
            while let Some(bytes) = input.next().await {
                let bytes = bytes.map_err(|_| PlatformFailure)?;
                ensure!(
                    expected < 0
                        || bytes.len() as u64 <= (expected as u64).saturating_sub(received),
                    ResourceUnavailable("storage download length exceeded")
                );
                received = received
                    .checked_add(bytes.len() as u64)
                    .context("storage size overflow")?;
                for chunk in bytes.chunks(64 * 1024) {
                    output
                        .send(Ok((chunk.to_vec(), expected)))
                        .await
                        .map_err(|_| failure("network download closed"))?;
                }
            }
            ensure!(
                expected < 0 || received == expected as u64,
                ResourceUnavailable("storage download ended early")
            );
            return Ok(());
        }
        Err(failure("too many storage redirects"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_directory_vectors_filter_children_and_encode_paths() {
        let client =
            HttpDirectory::new("https://example.test/archive/", "alice", "secret").unwrap();
        let html = r#"<a href="a%20b.txt">Wrong display</a><a href="child/">child</a><a href="a%20b.txt">dup</a>
<a href="../">parent</a><a href="https://evil.test/archive/secret">external</a><a href="/outside/secret">outside</a>
<a href="nested/deep.txt">nested</a><a href="%2e%2e/secret">escape</a><a href="%2Fsecret">separator</a>
<a href="secret?token=other">query</a><a href="javascript:alert(1)">script</a><script><a href="fake.txt">fake</a></script>"#;
        let entries = client
            .parse(html, &Url::parse("https://example.test/archive/").unwrap())
            .unwrap();
        assert_eq!(
            entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["a b.txt", "child"]
        );
        assert_eq!(entries[0].path, "/a b.txt");
        assert!(entries[1].is_directory);
        assert_eq!(
            client.url("/a b", true).unwrap().as_str(),
            "https://example.test/archive/a%20b/"
        );
        assert!(client.url("/../outside", false).is_err());
        for root in [
            "ftp://example.test/",
            "https://user:pass@example.test/",
            "https://example.test/a/../b",
            "https://example.test/%2e%2e/a",
            "https://example.test/?token=secret",
        ] {
            assert!(HttpDirectory::new(root, "", "").is_err(), "{root}");
        }
    }
}
