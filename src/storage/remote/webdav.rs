use crate::{
    management::reply::PlatformFailure,
    storage::remote::{
        DownloadPart, Entry,
        http_directory::{client, segments},
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use digest_auth::{AuthContext, HttpMethod, Qop, WwwAuthenticateHeader};
use futures_util::StreamExt;
use reqwest::{
    Client, Method, Response,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::mpsc;
use url::Url;
use zeroize::Zeroize;

const PROPFIND: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:creationdate/></d:prop></d:propfind>"#;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Extras {
    auth_type: AuthType,
    token: String,
    token_header_name: Option<String>,
    token_prefix: Option<String>,
    headers: BTreeMap<String, String>,
}
#[derive(Default, Deserialize, PartialEq)]
enum AuthType {
    #[default]
    Basic,
    Digest,
    Token,
}
struct Credentials {
    username: String,
    password: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
struct Digest {
    credentials: Credentials,
    challenge: Mutex<Option<WwwAuthenticateHeader>>,
}
#[derive(Clone)]
pub struct WebDav {
    root: Url,
    separator: String,
    headers: HeaderMap,
    digest: Option<Arc<Digest>>,
    client: Client,
    nextcloud_ids: bool,
}
fn value(text: &str) -> Result<HeaderValue> {
    let mut value = HeaderValue::from_str(text)?;
    value.set_sensitive(true);
    Ok(value)
}
fn tag<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case(name))
        .and_then(|n| n.text())
        .map(str::trim)
}
fn timestamp(value: Option<&str>) -> i64 {
    value
        .and_then(|v| OffsetDateTime::parse(v, &Rfc3339).ok())
        .and_then(|v| i64::try_from(v.unix_timestamp_nanos() / 1_000_000).ok())
        .unwrap_or(0)
}
impl WebDav {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        separator: &str,
        extras: &serde_json::Value,
    ) -> Result<Self> {
        let root = crate::storage::remote::http_directory::root_url(host.trim())?;
        let extras: Extras = serde_json::from_value(
            extras
                .get("webdav")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        let custom_auth = extras
            .headers
            .keys()
            .any(|k| k.trim().eq_ignore_ascii_case("authorization"));
        let mut headers = HeaderMap::new();
        if extras.auth_type == AuthType::Basic && !custom_auth {
            headers.insert(
                header::AUTHORIZATION,
                value(&format!(
                    "Basic {}",
                    STANDARD.encode(format!("{username}:{password}"))
                ))?,
            );
        }
        if extras.auth_type == AuthType::Token && !extras.token.trim().is_empty() {
            let name = extras
                .token_header_name
                .as_deref()
                .unwrap_or("Authorization")
                .trim();
            let name = if name.is_empty() {
                "Authorization"
            } else {
                name
            };
            let prefix = extras.token_prefix.as_deref().unwrap_or("Bearer").trim();
            let token = if prefix.is_empty() {
                extras.token.trim().to_owned()
            } else {
                format!("{prefix} {}", extras.token.trim())
            };
            headers.insert(HeaderName::from_bytes(name.as_bytes())?, value(&token)?);
        }
        for (name, content) in &extras.headers {
            if !name.trim().is_empty() {
                headers.insert(
                    HeaderName::from_bytes(name.trim().as_bytes())?,
                    value(content)?,
                );
            }
        }
        ensure!(headers.len() <= 128, "too many storage headers");
        for name in [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "trailer",
        ] {
            ensure!(
                !headers.contains_key(name),
                "storage header overrides HTTP framing"
            );
        }
        let digest = (extras.auth_type == AuthType::Digest && !custom_auth).then(|| {
            Arc::new(Digest {
                credentials: Credentials {
                    username: username.into(),
                    password: password.into(),
                },
                challenge: Mutex::new(None),
            })
        });
        Ok(Self {
            root,
            separator: if separator.is_empty() {
                "/".into()
            } else {
                separator.into()
            },
            headers,
            digest,
            client: client()?,
            nextcloud_ids: false,
        })
    }
    pub(crate) fn nextcloud(
        root: &str,
        user: &str,
        password: &str,
        separator: &str,
        client: Client,
    ) -> Result<Self> {
        let mut value = Self::new(root, user, password, separator, &serde_json::json!({}))?;
        value.client = client;
        value.nextcloud_ids = true;
        Ok(value)
    }
    pub fn transfer(&self) -> Result<Self> {
        let mut copy = self.clone();
        copy.client = client()?;
        if let Some(digest) = &self.digest {
            copy.digest = Some(Arc::new(Digest {
                credentials: Credentials {
                    username: digest.credentials.username.clone(),
                    password: digest.credentials.password.clone(),
                },
                challenge: Mutex::new(None),
            }));
        }
        Ok(copy)
    }
    pub(crate) fn normalize(&self, path: &str) -> Result<String> {
        let normalized = if self.separator == "/" {
            path.trim().to_owned()
        } else {
            path.trim().replace(&self.separator, "/")
        };
        let path = normalized.trim_matches('/');
        ensure!(
            path.is_empty()
                || path
                    .split('/')
                    .all(crate::storage::remote::http_directory::segment),
            "invalid remote path"
        );
        Ok(if normalized.is_empty() {
            "/".into()
        } else if normalized.starts_with('/') {
            normalized
        } else {
            format!("/{normalized}")
        })
    }
    fn url(&self, path: &str, directory: bool) -> Result<Url> {
        let normalized = self.normalize(path)?;
        let mut url = self.root.clone();
        let base = segments(&self.root).context("invalid WebDAV root")?;
        {
            let mut parts = url.path_segments_mut().map_err(|_| PlatformFailure)?;
            parts.clear().extend(base.iter().map(String::as_str));
            if normalized != "/" {
                parts.extend(normalized.trim_matches('/').split('/'));
            }
            if directory || normalized.ends_with('/') {
                parts.push("");
            }
        }
        Ok(url)
    }
    fn authorization(
        &self,
        method: &Method,
        url: &Url,
        body: Option<&[u8]>,
    ) -> Result<Option<HeaderValue>> {
        let Some(digest) = &self.digest else {
            return Ok(None);
        };
        let mut challenge = digest.challenge.lock().unwrap();
        let Some(challenge) = challenge.as_mut() else {
            return Ok(None);
        };
        let context = AuthContext::new_with_method(
            digest.credentials.username.as_str(),
            digest.credentials.password.as_str(),
            url.path(),
            body,
            HttpMethod::from(method.as_str()),
        );
        Ok(Some(value(
            &challenge
                .respond(&context)
                .map_err(|_| PlatformFailure)?
                .to_string(),
        )?))
    }
    fn challenge(&self, response: &Response) -> Result<()> {
        let digest = self.digest.as_ref().context(PlatformFailure)?;
        let header = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.trim_start().starts_with("Digest "))
            .context(PlatformFailure)?;
        // digest_auth indexes its parser by character count; only pass ASCII header syntax.
        ensure!(
            header.is_ascii() && header.len() <= 16 * 1024,
            PlatformFailure
        );
        let mut challenge = digest_auth::parse(header).map_err(|_| PlatformFailure)?;
        if let Some(qop) = &mut challenge.qop {
            // Streaming bodies cannot be replayed or prehashed; negotiate auth.
            ensure!(qop.contains(&Qop::AUTH), PlatformFailure);
            *qop = vec![Qop::AUTH];
        }
        *digest.challenge.lock().unwrap() = Some(challenge);
        Ok(())
    }
    fn request(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        digest: Option<HeaderValue>,
    ) -> reqwest::RequestBuilder {
        let mut all = headers;
        all.extend(self.headers.clone());
        if let Some(digest) = digest {
            all.insert(header::AUTHORIZATION, digest);
        }
        self.client.request(method, url).headers(all)
    }
    async fn buffered(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: &[u8],
        retry_auth: bool,
    ) -> Result<Response> {
        let auth = self.authorization(&method, &url, Some(body))?;
        let response = self
            .request(method.clone(), url.clone(), headers.clone(), auth)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && retry_auth
            && self.digest.is_some()
        {
            self.challenge(&response)?;
            drop(response);
            let auth = self.authorization(&method, &url, Some(body))?;
            return self
                .request(method, url, headers, auth)
                .body(body.to_vec())
                .send()
                .await
                .map_err(|_| PlatformFailure.into());
        }
        Ok(response)
    }
    async fn prepare_write(&self) -> Result<()> {
        if self.digest.is_some() {
            let headers = HeaderMap::from_iter([(
                HeaderName::from_static("depth"),
                HeaderValue::from_static("0"),
            )]);
            let response = self
                .buffered(
                    Method::from_bytes(b"PROPFIND")?,
                    self.url("/", true)?,
                    headers,
                    PROPFIND.as_bytes(),
                    true,
                )
                .await?;
            ensure!(response.status().is_success(), PlatformFailure);
        }
        Ok(())
    }
    pub fn parse(&self, xml: &str, requested: &str) -> Result<Vec<Entry>> {
        let document = if self.nextcloud_ids {
            crate::storage::remote::nextcloud::xml(xml)?
        } else {
            roxmltree::Document::parse_with_options(
                xml,
                roxmltree::ParsingOptions {
                    nodes_limit: 200_000,
                    ..Default::default()
                },
            )
            .map_err(|_| PlatformFailure)?
        };
        let base = segments(&self.root).context(PlatformFailure)?;
        let requested = self.normalize(requested)?;
        let requested = requested.trim_end_matches('/');
        let mut entries = vec![];
        for response in document
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("response"))
        {
            ensure!(entries.len() < 100_000, PlatformFailure);
            let Some(href) = tag(response, "href") else {
                continue;
            };
            let href = href.split(['?', '#']).next().unwrap_or("");
            let href = if href.contains("://") {
                match Url::parse(href) {
                    Ok(url) => url.path().to_owned(),
                    Err(_) => continue,
                }
            } else {
                format!("/{}", href.trim_start_matches('/'))
            };
            if !crate::storage::remote::http_directory::raw_path_safe(&href) {
                continue;
            }
            let href_url = match self.root.join(&href) {
                Ok(url) => url,
                Err(_) => continue,
            };
            let Some(parts) = segments(&href_url) else {
                continue;
            };
            if !parts.starts_with(&base) {
                continue;
            }
            let mut remote = format!("/{}", parts[base.len()..].join("/"));
            if href.ends_with('/') && remote != "/" {
                remote.push('/');
            }
            let Ok(normalized) = self.normalize(&remote) else {
                continue;
            };
            if normalized.trim_end_matches('/') == requested {
                continue;
            }
            let name = tag(response, "displayname")
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    normalized
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .into()
                });
            let directory = href.ends_with('/')
                || response.descendants().any(|n| {
                    n.is_element() && n.tag_name().name().eq_ignore_ascii_case("collection")
                });
            let path = if self.separator == "/" {
                normalized
            } else {
                normalized.replace('/', &self.separator)
            };
            entries.push(Entry {
                name: name.clone(),
                path,
                is_directory: directory,
                size: if directory {
                    -1
                } else {
                    tag(response, "getcontentlength")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0)
                },
                created_date: if directory {
                    -1
                } else {
                    timestamp(tag(response, "creationdate"))
                },
                updated_date: if directory {
                    -1
                } else if self.nextcloud_ids {
                    crate::storage::remote::nextcloud::http_date(tag(response, "getlastmodified"))
                } else {
                    timestamp(tag(response, "getlastmodified"))
                },
                is_hidden: name.starts_with('.'),
                is_symbolic_link: false,
                is_symbolic_link_known: false,
                reference: if self.nextcloud_ids {
                    Some(serde_json::json!({"id":crate::storage::remote::nextcloud::file_id(response)?}))
                } else {
                    None
                },
            });
        }
        Ok(entries)
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let headers = HeaderMap::from_iter([
            (
                HeaderName::from_static("depth"),
                HeaderValue::from_static("1"),
            ),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            ),
            (header::ACCEPT, HeaderValue::from_static("application/xml")),
        ]);
        let response = self
            .buffered(
                Method::from_bytes(b"PROPFIND")?,
                self.url(path, true)?,
                headers,
                PROPFIND.as_bytes(),
                true,
            )
            .await?;
        ensure!(response.status().is_success(), PlatformFailure);
        let mut stream = response.bytes_stream();
        let mut bytes = vec![];
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PlatformFailure)?;
            ensure!(
                chunk.len() <= 8 * 1024 * 1024 - bytes.len(),
                PlatformFailure
            );
            bytes.extend(chunk);
        }
        let xml = String::from_utf8(bytes).map_err(|_| PlatformFailure)?;
        let owner = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || owner.parse(&xml, &path)).await?
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let headers = HeaderMap::from_iter([(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        )]);
        let response = self
            .buffered(Method::GET, self.url(path, false)?, headers, &[], true)
            .await?;
        ensure!(response.status().is_success(), PlatformFailure);
        let total = response
            .content_length()
            .filter(|v| *v > 0)
            .map(i64::try_from)
            .transpose()?
            .unwrap_or(size.max(0));
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| PlatformFailure)?;
            for bytes in chunk.chunks(64 * 1024) {
                output
                    .send(Ok((bytes.to_vec(), total)))
                    .await
                    .map_err(|_| PlatformFailure)?;
            }
        }
        Ok(())
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        new_path: &str,
        directory: bool,
    ) -> Result<bool> {
        let mut headers = HeaderMap::new();
        let (method, target) = match operation {
            "/mkdir" => (Method::from_bytes(b"MKCOL")?, self.url(path, true)?),
            "/create" => {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                (Method::PUT, self.url(path, false)?)
            }
            "/delete" => (Method::DELETE, self.url(path, directory)?),
            "/copy" | "/rename" | "/move" => {
                let source = self.normalize(path)?;
                let destination = self.normalize(new_path)?;
                if operation == "/copy" {
                    ensure!(
                        source != "/" && destination != "/",
                        "invalid copy destination"
                    );
                }
                if operation == "/move" {
                    ensure!(
                        source != "/"
                            && source.trim_end_matches('/') != destination.trim_end_matches('/')
                            && !destination
                                .starts_with(&format!("{}/", source.trim_end_matches('/'))),
                        "invalid move destination"
                    );
                }
                headers.insert(
                    HeaderName::from_static("destination"),
                    HeaderValue::from_str(self.url(new_path, false)?.as_str())?,
                );
                headers.insert(
                    HeaderName::from_static("overwrite"),
                    HeaderValue::from_static(if operation == "/move" { "F" } else { "T" }),
                );
                (
                    Method::from_bytes(if operation == "/copy" {
                        b"COPY"
                    } else {
                        b"MOVE"
                    })?,
                    self.url(path, false)?,
                )
            }
            _ => return Err(PlatformFailure.into()),
        };
        self.prepare_write().await?;
        let response = self.buffered(method, target, headers, &[], false).await?;
        ensure!(response.status().is_success(), PlatformFailure);
        Ok(true)
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<bool> {
        ensure!(size >= 0, PlatformFailure);
        let url = self.url(path, false)?;
        self.prepare_write().await?;
        let auth = self.authorization(&Method::PUT, &url, None)?;
        let counter = consumed.clone();
        let stream = futures_util::stream::try_unfold((input, 0u64), move |(mut input, count)| {
            let counter = counter.clone();
            async move {
                match input.recv().await {
                    Some(bytes) => {
                        let next = count
                            .checked_add(bytes.len() as u64)
                            .ok_or_else(|| std::io::Error::other("upload size overflow"))?;
                        if next > size as u64 {
                            return Err(std::io::Error::other("upload length exceeded"));
                        }
                        counter.store(next, Ordering::Release);
                        Ok(Some((bytes, (input, next))))
                    }
                    None if count == size as u64 => Ok(None),
                    None => Err(std::io::Error::other("upload ended early")),
                }
            }
        });
        let headers = HeaderMap::from_iter([
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&size.to_string())?,
            ),
        ]);
        let response = self
            .request(Method::PUT, url, headers, auth)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(
            response.status().is_success() && consumed.load(Ordering::Acquire) == size as u64,
            PlatformFailure
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_preserve_encoding_separator_and_safe_root() {
        let client = WebDav::new(
            "http://example.test/dav/",
            "",
            "",
            "\\",
            &serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(
            client.url("\\child\\中文 &.txt", false).unwrap().as_str(),
            "http://example.test/dav/child/%E4%B8%AD%E6%96%87%20&.txt"
        );
        assert_eq!(
            client.url("\\child\\", false).unwrap().as_str(),
            "http://example.test/dav/child/"
        );
        assert!(client.url("\\..\\escape", false).is_err());
        for extras in [
            serde_json::json!({"webdav":{"headers":{"Content-Length":"100"}}}),
            serde_json::json!({"webdav":{"headers":{"X-Test":"bad\r\nInjected: value"}}}),
            serde_json::json!({"webdav":{"authType":"invalid"}}),
        ] {
            assert!(WebDav::new("http://example.test/dav/", "", "", "/", &extras).is_err());
        }
        let xml = r#"<multistatus xmlns="DAV:"><response><href>/dav/child/</href><propstat><prop><resourcetype><collection/></resourcetype></prop></propstat></response></multistatus>"#;
        let entries = client.parse(xml, "\\").unwrap();
        assert_eq!(entries[0].path, "\\child\\");
        assert_eq!(entries[0].name, "child");
        assert!(
            client
                .parse(
                    r#"<!DOCTYPE root [<!ENTITY x "expanded">]><root>&x;</root>"#,
                    "\\"
                )
                .is_err()
        );
    }
}
