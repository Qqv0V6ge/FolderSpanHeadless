use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::{DownloadPart, Entry, http_directory::client, safe_segment},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{
    Client, Method, Response,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroize;

const XML_LIMIT: usize = 8 * 1024 * 1024;
const ENTRY_LIMIT: usize = 500_000;
const NAME_BYTES_LIMIT: usize = 64 * 1024 * 1024;
const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    #[serde(default)]
    bucket: String,
    #[serde(default = "default_region")]
    region: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    force_path_style: bool,
    #[serde(default)]
    session_token: String,
}
fn default_region() -> String {
    "us-east-1".into()
}
impl Drop for Settings {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}
struct Credentials {
    access: String,
    secret: String,
    settings: Settings,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
#[derive(Clone)]
pub struct S3 {
    endpoint: Option<Url>,
    separator: String,
    credentials: Arc<Credentials>,
    client: Client,
}
struct Page {
    prefixes: Vec<String>,
    objects: Vec<Object>,
    cursor: Option<String>,
}
struct Object {
    key: String,
    size: i64,
    modified: i64,
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
fn signed_headers(
    method: &Method,
    path: &str,
    query: &str,
    host: &str,
    auth: &Credentials,
    date: &str,
    copy: Option<&str>,
) -> Result<HeaderMap> {
    let hash = if copy.is_some() {
        EMPTY_HASH
    } else {
        "UNSIGNED-PAYLOAD"
    };
    let mut fields = BTreeMap::from([
        ("host", host.to_owned()),
        ("x-amz-content-sha256", hash.into()),
        ("x-amz-date", date.into()),
    ]);
    let token = auth.settings.session_token.trim();
    if !token.is_empty() {
        fields.insert("x-amz-security-token", token.into());
    }
    if let Some(copy) = copy {
        fields.insert("x-amz-copy-source", copy.into());
    }
    let names = fields.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_headers = fields
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}:{}\n",
                value.split_whitespace().collect::<Vec<_>>().join(" ")
            )
        })
        .collect::<String>();
    let canonical = format!("{method}\n{path}\n{query}\n{canonical_headers}\n{names}\n{hash}");
    let day = &date[..8];
    let scope = format!("{day}/{}/s3/aws4_request", auth.settings.region.trim());
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical))
    );
    let mut secret = format!("AWS4{}", auth.secret);
    let mut key = hmac(secret.as_bytes(), day);
    secret.zeroize();
    for text in [auth.settings.region.trim(), "s3", "aws4_request"] {
        let next = hmac(&key, text);
        key.zeroize();
        key = next;
    }
    let signature = hex::encode(hmac(&key, &to_sign));
    key.zeroize();
    fields.insert(
        "authorization",
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
            auth.access
        ),
    );
    let mut headers = HeaderMap::new();
    for (name, content) in fields {
        let mut value = HeaderValue::from_str(&content)?;
        value.set_sensitive(matches!(name, "authorization" | "x-amz-security-token"));
        headers.insert(HeaderName::from_bytes(name.as_bytes())?, value);
    }
    Ok(headers)
}
fn tag<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(str::trim)
}
fn document(xml: &str) -> Result<roxmltree::Document<'_>> {
    roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 200_000,
            ..Default::default()
        },
    )
    .map_err(|_| PlatformFailure.into())
}
fn parse_page(xml: &str) -> Result<Page> {
    let doc = document(xml).map_err(|_| anyhow::anyhow!("invalid S3 directory XML"))?;
    let root = doc.root_element();
    ensure!(
        root.tag_name().name() == "ListBucketResult",
        "invalid S3 directory page"
    );
    let truncated = match tag(root, "IsTruncated") {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(anyhow::anyhow!("invalid S3 directory page")),
    };
    let cursor = tag(root, "NextContinuationToken")
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    ensure!(truncated == cursor.is_some(), "invalid S3 directory page");
    let mut prefixes = vec![];
    let mut objects = vec![];
    for child in root.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "CommonPrefixes" => {
                if let Some(prefix) = tag(child, "Prefix").filter(|s| !s.is_empty()) {
                    prefixes.push(prefix.into());
                }
            }
            "Contents" => {
                let Some(key) = tag(child, "Key").filter(|s| !s.is_empty()) else {
                    continue;
                };
                let size = tag(child, "Size")
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|n| *n >= 0)
                    .context("invalid S3 directory page")?;
                let modified = tag(child, "LastModified")
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.timestamp_millis())
                    .unwrap_or(0);
                objects.push(Object {
                    key: key.into(),
                    size,
                    modified,
                });
            }
            _ => {}
        }
    }
    Ok(Page {
        prefixes,
        objects,
        cursor,
    })
}
async fn xml(response: Response) -> Result<String> {
    ensure!(response.status().is_success(), PlatformFailure);
    let mut stream = response.bytes_stream();
    let mut bytes = vec![];
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| PlatformFailure)?;
        ensure!(chunk.len() <= XML_LIMIT - bytes.len(), PlatformFailure);
        bytes.extend(chunk);
    }
    String::from_utf8(bytes).map_err(|_| PlatformFailure.into())
}
fn cursor(next: &Option<String>, seen: &mut HashSet<String>) -> Result<()> {
    if let Some(next) = next {
        ensure!(
            next.len() <= 64 * 1024 && seen.insert(next.clone()),
            ResourceUnavailable("S3 pagination cursor is invalid or repeated")
        );
    }
    Ok(())
}
fn directory(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.into()
    } else {
        format!("{key}/")
    }
}
fn safe_key(key: &str) -> bool {
    !key.is_empty() && key.trim_end_matches('/').split('/').all(safe_segment)
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
impl S3 {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        separator: &str,
        extras: &serde_json::Value,
    ) -> Result<Self> {
        let settings: Settings =
            serde_json::from_value(extras.get("s3").cloned().unwrap_or(serde_json::json!({})))?;
        let endpoint = if settings.endpoint.trim().is_empty() {
            host.trim()
        } else {
            settings.endpoint.trim()
        };
        let endpoint = (!endpoint.is_empty())
            .then(|| crate::storage::remote::http_directory::root_url(endpoint))
            .transpose()?;
        Ok(Self {
            endpoint,
            separator: if separator.is_empty() {
                "/".into()
            } else {
                separator.into()
            },
            credentials: Arc::new(Credentials {
                access: username.trim().into(),
                secret: password.into(),
                settings,
            }),
            client: client()?,
        })
    }
    pub fn transfer(&self) -> Result<Self> {
        let mut copy = self.clone();
        copy.client = client()?;
        Ok(copy)
    }
    fn key(&self, path: &str, trailing: bool) -> Result<String> {
        let path = path.trim().replace(&self.separator, "/");
        let key = path.strip_prefix('/').unwrap_or(&path).trim();
        let key = if trailing {
            key
        } else {
            key.trim_end_matches('/')
        };
        ensure!(key.is_empty() || safe_key(key), "invalid S3 path");
        Ok(key.into())
    }
    fn request(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(&str, &str)],
        copy: Option<&str>,
    ) -> Result<reqwest::RequestBuilder> {
        let settings = &self.credentials.settings;
        let bucket = settings.bucket.trim();
        ensure!(
            !settings.bucket.trim().is_empty()
                && settings
                    .bucket
                    .trim()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "invalid S3 bucket"
        );
        ensure!(
            !settings.region.trim().is_empty()
                && !self.credentials.access.is_empty()
                && !self.credentials.secret.trim().is_empty(),
            "S3 credentials and region required"
        );
        let endpoint = self.endpoint.as_ref().context("S3 endpoint required")?;
        let mut url = endpoint.clone();
        if !settings.force_path_style {
            let host = format!("{bucket}.{}", url.host_str().context("S3 host required")?);
            url.set_host(Some(&host))?;
        }
        let mut segments = endpoint
            .path()
            .trim_matches('/')
            .split('/')
            .filter(|p| !p.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if settings.force_path_style {
            segments.push(bucket.into());
        }
        let key = key.unwrap_or("").trim();
        if !key.trim_matches('/').is_empty() {
            segments.extend(key.trim_matches('/').split('/').map(encode));
        }
        let mut path = format!("/{}", segments.join("/"));
        if key.ends_with('/') && path != "/" {
            path.push('/');
        }
        url.set_path(&path);
        // The signer must see exactly the path sent by the HTTP client.
        ensure!(url.path() == path, "S3 endpoint changes the canonical path");
        let mut query = query.to_vec();
        query.sort_unstable();
        let query = query
            .into_iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.set_query((!query.is_empty()).then_some(&query));
        let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
        let headers = signed_headers(
            &method,
            &path,
            &query,
            host,
            &self.credentials,
            &Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
            copy,
        )?;
        Ok(self.client.request(method, url).headers(headers))
    }
    async fn send(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(&str, &str)],
    ) -> Result<Response> {
        self.request(method, key, query, None)?
            .send()
            .await
            .map_err(|_| PlatformFailure.into())
    }
    async fn page(&self, prefix: &str, delimiter: bool, next: &Option<String>) -> Result<Page> {
        let mut query = vec![("list-type", "2")];
        if delimiter {
            query.push(("delimiter", "/"));
        }
        if !prefix.is_empty() {
            query.push(("prefix", prefix));
        }
        if let Some(next) = next {
            query.push(("continuation-token", next));
        }
        parse_page(&xml(self.send(Method::GET, None, &query).await?).await?)
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let current = self.key(path, false)?;
        let prefix = directory(&current);
        let mut next = None;
        let mut seen_cursors = HashSet::new();
        let mut seen_paths = HashSet::new();
        let mut entries = vec![];
        let mut name_bytes = 0;
        loop {
            let page = self.page(&prefix, true, &next).await?;
            for (key, is_directory, size, date) in page
                .prefixes
                .into_iter()
                .map(|p| (p.trim_end_matches('/').to_owned(), true, -1, -1))
                .chain(
                    page.objects
                        .into_iter()
                        .filter(|o| {
                            let relative = o.key.strip_prefix(&prefix);
                            relative.is_some_and(|s| {
                                !s.is_empty() && !s.contains('/') && safe_segment(s)
                            })
                        })
                        .map(|o| (o.key, false, o.size, o.modified)),
                )
            {
                if key == current || !safe_key(&key) || !seen_paths.insert(key.clone()) {
                    continue;
                }
                name_bytes += key.len();
                ensure!(
                    name_bytes <= NAME_BYTES_LIMIT,
                    ResourceUnavailable("S3 directory names exceed the byte limit")
                );
                let name = key.rsplit('/').next().unwrap_or("").to_owned();
                entries.push(Entry {
                    is_hidden: name.starts_with('.'),
                    name,
                    path: format!("/{key}"),
                    is_directory,
                    size,
                    created_date: date,
                    updated_date: date,
                    is_symbolic_link: false,
                    is_symbolic_link_known: true,
                    reference: None,
                });
                ensure!(
                    entries.len() <= ENTRY_LIMIT,
                    ResourceUnavailable("S3 directory exceeds the entry limit")
                );
            }
            next = page.cursor;
            cursor(&next, &mut seen_cursors)?;
            if next.is_none() {
                break;
            }
        }
        Ok(entries)
    }
    async fn keys(&self, prefix: &str) -> Result<Vec<String>> {
        let mut next = None;
        let mut seen = HashSet::new();
        let mut keys = vec![];
        let mut name_bytes = 0;
        loop {
            let page = self.page(prefix, false, &next).await?;
            for object in page.objects {
                // Do not let a malformed listing turn recursive deletion into a bucket-wide write.
                ensure!(
                    object.key.starts_with(prefix) && safe_key(&object.key),
                    PlatformFailure
                );
                name_bytes += object.key.len();
                ensure!(
                    name_bytes <= NAME_BYTES_LIMIT,
                    ResourceUnavailable("S3 directory names exceed the byte limit")
                );
                keys.push(object.key);
                ensure!(
                    keys.len() <= ENTRY_LIMIT,
                    ResourceUnavailable("S3 directory exceeds the entry limit")
                );
            }
            next = page.cursor;
            cursor(&next, &mut seen)?;
            if next.is_none() {
                break;
            }
        }
        Ok(keys)
    }
    async fn empty(&self, key: &str) -> Result<()> {
        let response = self
            .request(Method::PUT, Some(key), &[], None)?
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Vec::new())
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(response.status().is_success(), PlatformFailure);
        Ok(())
    }
    async fn markers(&self, key: &str, include_self: bool) -> Result<()> {
        let segments = key
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>();
        let count = if include_self {
            segments.len()
        } else {
            segments.len().saturating_sub(1)
        };
        let mut marker = String::new();
        for part in segments.iter().take(count) {
            marker.push_str(part);
            marker.push('/');
            if !self
                .send(Method::HEAD, Some(&marker), &[])
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                self.empty(&marker).await?;
            }
        }
        Ok(())
    }
    async fn delete(&self, key: &str) -> Result<()> {
        ensure!(
            self.send(Method::DELETE, Some(key), &[])
                .await?
                .status()
                .is_success(),
            PlatformFailure
        );
        Ok(())
    }
    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let source = format!(
            "{}/{}",
            self.credentials.settings.bucket.trim(),
            from.trim_matches('/')
                .split('/')
                .map(encode)
                .collect::<Vec<_>>()
                .join("/")
        );
        let source = if from.ends_with('/') {
            format!("{source}/")
        } else {
            source
        };
        let response = self
            .request(Method::PUT, Some(to), &[], Some(&source))?
            .body(Vec::new())
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        let xml = xml(response).await?;
        let doc = document(&xml)?;
        let root = doc.root_element();
        ensure!(
            root.tag_name().name() == "CopyObjectResult"
                && tag(root, "ETag").is_some_and(|s| !s.is_empty())
                && tag(root, "LastModified").is_some_and(|s| !s.is_empty()),
            PlatformFailure
        );
        Ok(())
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        destination: &str,
        is_directory: bool,
    ) -> Result<bool> {
        let from = self.key(path, true)?;
        if operation == "/mkdir" {
            if !from.is_empty() {
                self.markers(&from, true).await?;
            }
            return Ok(true);
        }
        ensure!(!from.is_empty(), "cannot mutate S3 root");
        match operation {
            "/create" => {
                let key = self.key(path, false)?;
                self.markers(&key, false).await?;
                self.empty(&key).await?;
            }
            "/delete-empty-directory" => {
                ensure!(
                    self.list(path).await?.is_empty(),
                    ResourceUnavailable("S3 directory is not empty")
                );
                self.delete(&directory(&from)).await?;
            }
            "/delete" if is_directory => {
                let prefix = directory(&from);
                let keys = self.keys(&prefix).await?;
                if keys.is_empty() {
                    let _ = self.delete(&prefix).await;
                }
                for key in keys {
                    self.delete(&key).await?;
                }
            }
            "/delete" => self.delete(from.trim_end_matches('/')).await?,
            "/copy" => {
                let to = self.key(destination, false)?;
                ensure!(!to.is_empty(), "invalid S3 copy destination");
                self.copy(from.trim_end_matches('/'), &to).await?;
            }
            "/rename" | "/move" => {
                let to = self.key(destination, true)?;
                ensure!(!to.is_empty(), "invalid S3 rename destination");
                if operation == "/move" {
                    let source = from.trim_end_matches('/');
                    let target = to.trim_end_matches('/');
                    ensure!(
                        source != target && !target.starts_with(&format!("{source}/")),
                        "invalid move destination"
                    );
                    let (parent, name) = destination.rsplit_once('/').unwrap_or(("/", destination));
                    let entries = self
                        .list(if parent.is_empty() { "/" } else { parent })
                        .await
                        .map_err(|_| {
                            ResourceUnavailable("cannot verify move destination is absent")
                        })?;
                    ensure!(
                        !entries.iter().any(|e| e.name == name),
                        ResourceUnavailable("move target already exists")
                    );
                }
                let is_dir = if from.ends_with('/') {
                    true
                } else if self
                    .send(Method::HEAD, Some(&from), &[])
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    false
                } else {
                    let prefix = directory(&from);
                    match self
                        .send(
                            Method::GET,
                            None,
                            &[("list-type", "2"), ("prefix", &prefix), ("max-keys", "1")],
                        )
                        .await
                    {
                        Ok(response) if response.status().is_success() => {
                            let page = parse_page(&xml(response).await?)?;
                            !page.objects.is_empty() || !page.prefixes.is_empty()
                        }
                        _ => false,
                    }
                };
                if is_dir {
                    let source = directory(&from);
                    let target = directory(&to);
                    if source == target {
                        return Ok(true);
                    }
                    let keys = self.keys(&source).await?;
                    for key in &keys {
                        self.copy(
                            key,
                            &format!(
                                "{target}{}",
                                key.strip_prefix(&source).context(PlatformFailure)?
                            ),
                        )
                        .await?;
                    }
                    for key in keys {
                        self.delete(&key).await?;
                    }
                } else {
                    self.copy(&from, &to).await?;
                    self.delete(&from).await?;
                }
            }
            _ => return Err(PlatformFailure.into()),
        }
        Ok(true)
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let key = self.key(path, false)?;
        ensure!(!key.is_empty(), "S3 object required");
        let response = self
            .request(Method::GET, Some(&key), &[], None)?
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(response.status().is_success(), PlatformFailure);
        let total = response
            .content_length()
            .filter(|n| *n > 0)
            .map(i64::try_from)
            .transpose()?
            .unwrap_or(size.max(0));
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            for bytes in chunk.map_err(|_| PlatformFailure)?.chunks(64 * 1024) {
                output
                    .send(Ok((bytes.to_vec(), total)))
                    .await
                    .map_err(|_| PlatformFailure)?;
            }
        }
        Ok(())
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
        cancel: &CancellationToken,
    ) -> Result<bool> {
        ensure!(size >= 0, PlatformFailure);
        let key = self.key(path, false)?;
        ensure!(!key.is_empty(), "S3 object required");
        let size = size as u64;
        let reader = Arc::new(Mutex::new(UploadReader {
            input,
            pending: vec![],
            offset: 0,
            read: 0,
            consumed,
        }));
        let mut upload_id = None;
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ResourceUnavailable("network transfer closed").into()),
            result = async {
                self.markers(&key,false).await?;
                if size < 16*1024*1024 {
                    self.upload_part(&key,size,&[],reader.clone()).await?;
                } else {
                    let text = xml(self.request(Method::POST,Some(&key),&[("uploads","")],None)?.body(Vec::new()).send().await.map_err(|_| PlatformFailure)?).await?;
                    let id = {
                        let doc = document(&text)?;
                        ensure!(doc.root_element().tag_name().name() == "InitiateMultipartUploadResult",PlatformFailure);
                        tag(doc.root_element(),"UploadId").filter(|s| !s.is_empty() && s.len() <= 64*1024).context(PlatformFailure)?.to_owned()
                    };
                    upload_id = Some(id.clone());
                    let part_size = (8*1024*1024u64).max(size.div_ceil(10_000));
                    let mut parts = String::from("<CompleteMultipartUpload>");
                    let mut offset = 0;
                    let mut part = 1;
                    while offset < size {
                        let length = part_size.min(size-offset);
                        let number = part.to_string();
                        let etag = self.upload_part(&key,length,&[("uploadId",&id),("partNumber",&number)],reader.clone()).await?;
                        ensure!(!etag.is_empty(),PlatformFailure);
                        parts.push_str(&format!("<Part><PartNumber>{part}</PartNumber><ETag>&quot;{}&quot;</ETag></Part>",escape(&etag)));
                        ensure!(parts.len() <= XML_LIMIT, PlatformFailure);
                        offset += length; part += 1;
                    }
                    reader.lock().await.finish(size).await?;
                    parts.push_str("</CompleteMultipartUpload>");
                    let text = xml(self.request(Method::POST,Some(&key),&[("uploadId",&id)],None)?
                        .header(header::CONTENT_TYPE,"application/xml").body(parts).send().await.map_err(|_| PlatformFailure)?).await?;
                    let doc = document(&text)?;
                    // S3 can embed an error after sending HTTP 200; never report that as committed.
                    ensure!(doc.root_element().tag_name().name() == "CompleteMultipartUploadResult"
                        && tag(doc.root_element(),"ETag").is_some_and(|s| !s.is_empty())
                        && !doc.descendants().any(|n| n.is_element() && n.tag_name().name() == "Error"),PlatformFailure);
                    return Ok(true);
                }
                reader.lock().await.finish(size).await?;
                Ok(true)
            } => result,
        };
        if result.is_err() {
            if let Some(id) = upload_id {
                // Cleanup only the uncommitted multipart ID; never delete or replay an uncertain object write.
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    self.send(Method::DELETE, Some(&key), &[("uploadId", &id)]),
                )
                .await;
            }
        }
        result
    }
    async fn upload_part(
        &self,
        key: &str,
        length: u64,
        query: &[(&str, &str)],
        reader: Arc<Mutex<UploadReader>>,
    ) -> Result<String> {
        let start = reader.lock().await.read;
        let stream = futures_util::stream::try_unfold(
            (reader.clone(), length),
            |(reader, remaining)| async move {
                if remaining == 0 {
                    return Ok::<_, std::io::Error>(None);
                }
                let bytes = reader.lock().await.next(remaining).await?;
                if bytes.is_empty() {
                    return Err(std::io::Error::other("S3 upload ended early"));
                }
                let remaining = remaining - bytes.len() as u64;
                Ok(Some((bytes, (reader, remaining))))
            },
        );
        let response = self
            .request(Method::PUT, Some(key), query, None)?
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, length)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(
            response.status().is_success() && reader.lock().await.read == start + length,
            PlatformFailure
        );
        Ok(response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .into())
    }
}

struct UploadReader {
    input: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
    read: u64,
    consumed: Arc<AtomicU64>,
}
impl UploadReader {
    async fn next(&mut self, max: u64) -> std::io::Result<Vec<u8>> {
        while self.offset == self.pending.len() {
            match self.input.recv().await {
                Some(bytes) => {
                    self.pending = bytes;
                    self.offset = 0;
                }
                None => return Ok(vec![]),
            }
        }
        let length = (self.pending.len() - self.offset)
            .min(64 * 1024)
            .min(usize::try_from(max).unwrap_or(usize::MAX));
        let bytes = self.pending[self.offset..self.offset + length].to_vec();
        self.offset += length;
        self.read += length as u64;
        self.consumed.store(self.read, Ordering::Release);
        Ok(bytes)
    }
    async fn finish(&mut self, size: u64) -> Result<()> {
        ensure!(
            self.read == size && self.next(1).await?.is_empty(),
            ResourceUnavailable("upload length mismatch")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_xml_and_pagination_fail_closed() {
        let s3 = S3::new(
            "https://example.test/base%20path",
            "access",
            "secret",
            "\\",
            &serde_json::json!({"s3":{"bucket":"test","forcePathStyle":true}}),
        )
        .unwrap();
        let request = s3
            .request(
                Method::GET,
                Some("中文 &/100%.txt"),
                &[("prefix", "中 /+"), ("list-type", "2")],
                None,
            )
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://example.test/base%20path/test/%E4%B8%AD%E6%96%87%20%26/100%25.txt?list-type=2&prefix=%E4%B8%AD%20%2F%2B"
        );
        assert_eq!(s3.key(" \\a\\b  ", false).unwrap(), "a/b");
        for p in ["/a/../b", "//a", "/a//b", "/a/./b", "/a\0b"] {
            assert!(s3.key(p, false).is_err(), "{p}");
        }
        for xml in [
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            "<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken>x</NextContinuationToken></ListBucketResult>",
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>x</Key><Size>-1</Size></Contents></ListBucketResult>",
            "<ListBucketResult>",
            "<!DOCTYPE x [<!ENTITY a 'x'>]><ListBucketResult><IsTruncated>false</IsTruncated><X>&a;</X></ListBucketResult>",
        ] {
            assert!(parse_page(xml).is_err());
        }
        let p = parse_page("<ListBucketResult xmlns='urn:test'><IsTruncated>false</IsTruncated><Contents><Key>中 &amp;.txt</Key><Size>5</Size><LastModified>2020-01-01T00:00:00Z</LastModified></Contents></ListBucketResult>").unwrap();
        assert_eq!(p.objects[0].key, "中 &.txt");
        assert_eq!(p.objects[0].modified, 1577836800000);
        let virtual_host = S3::new("invalid host ignored by explicit endpoint", "access", "secret", "/",
            &serde_json::json!({"s3":{"bucket":"test","endpoint":"https://example.test:9443/base"}})).unwrap();
        let request = virtual_host
            .request(Method::GET, Some("one/two/"), &[], None)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.url().as_str(),
            "https://test.example.test:9443/base/one/two/"
        );
        assert_eq!(request.headers()[header::HOST], "test.example.test:9443");
        assert!(request.headers()[header::AUTHORIZATION].is_sensitive());
        assert!(!request.headers().contains_key("x-amz-security-token"));
        let mut seen = HashSet::new();
        cursor(&Some("next".into()), &mut seen).unwrap();
        assert!(cursor(&Some("next".into()), &mut seen).is_err());
        assert!(cursor(&Some("x".repeat(65537)), &mut seen).is_err());
    }
}
