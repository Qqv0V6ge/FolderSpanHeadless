mod advanced;
use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::{
        accounts::{Kind, Storage, canonical_server, string},
        http::{checked_path, success, text},
        remote::{DownloadPart, Entry, http_directory::client, safe_segment},
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
use url::Url;

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Options {
    account_id: String,
    connection_id: String,
    root_id: String,
    library_id: String,
    read_only: bool,
    seafile_repo_token: bool,
}
#[derive(Clone)]
pub struct Seafile {
    server: String,
    options: Options,
    root: String,
    store: Arc<Storage>,
    client: Client,
}
#[derive(Debug)]
struct Missing;
impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Storage entry not found")
    }
}
impl std::error::Error for Missing {}
fn path(value: &str) -> Result<String> {
    checked_path(value)?;
    Ok(if value.trim_end_matches('/').is_empty() {
        "/".into()
    } else {
        value.trim_end_matches('/').into()
    })
}
fn library(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn long(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}
impl Seafile {
    pub fn new(host: &str, extras: &Value, store: Arc<Storage>) -> Result<Self> {
        let server = canonical_server(host)?;
        let options: Options =
            serde_json::from_value(extras.get("cloud").cloned().unwrap_or(json!({})))?;
        ensure!(library(&options.library_id), "Select a Seafile library");
        let root = path(if options.root_id.trim().is_empty() {
            "/"
        } else {
            &options.root_id
        })?
        .trim_end_matches('/')
        .to_owned();
        Ok(Self {
            server,
            options,
            root,
            store,
            client: client()?,
        })
    }
    pub fn capabilities(&self) -> Value {
        let a = self
            .store
            .metadata(&self.options.account_id)
            .ok()
            .filter(|a| {
                a.kind == Kind::Seafile && !a.requires_authorization && !a.access_token.is_empty()
            });
        let read = a.is_some();
        let write = a.is_some_and(|a| !a.read_only && !self.options.read_only);
        json!({"read":read,"write":write,"delete":write,"rename":write,"sync":true})
    }
    pub fn writable(&self) -> bool {
        self.capabilities()["write"] == true
    }
    fn remote(&self, value: &str) -> Result<String> {
        Ok(format!("{}{}", self.root, path(value)?))
    }
    fn url(&self, operation: &str, remote: Option<&str>, file: bool) -> Result<Url> {
        ensure!(safe_segment(operation), "invalid Seafile operation");
        let mut u = Url::parse(&self.server)?;
        {
            let mut p = u
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid storage server"))?;
            p.pop_if_empty();
            if self.options.seafile_repo_token {
                p.extend(["api", "v2.1", "via-repo-token", operation, ""]);
            } else if file {
                p.extend([
                    "api",
                    "v2.1",
                    "repos",
                    &self.options.library_id,
                    operation,
                    "",
                ]);
            } else {
                p.extend(["api2", "repos", &self.options.library_id, operation, ""]);
            }
        }
        if let Some(remote) = remote {
            u.query_pairs_mut().append_pair(
                if self.options.seafile_repo_token {
                    "path"
                } else {
                    "p"
                },
                remote,
            );
        }
        Ok(u)
    }
    async fn request(
        &self,
        method: Method,
        url: Url,
        form: Option<&[(&str, String)]>,
    ) -> Result<Value> {
        let mut request = self.authorized(method, url)?;
        if let Some(form) = form {
            request = request.form(form);
        }
        self.execute(request).await
    }
    fn authorized(&self, method: Method, url: Url) -> Result<reqwest::RequestBuilder> {
        let account = self.store.credential(
            "Seafile",
            &self.server,
            &self.options.account_id,
            &self.options.library_id,
        )?;
        Ok(self
            .client
            .request(method, url)
            .bearer_auth(&account.access_token))
    }
    async fn execute(&self, request: reqwest::RequestBuilder) -> Result<Value> {
        let body = text(success(request.send().await.map_err(|_| PlatformFailure)?)?).await?;
        if body.trim().is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&body)
                .map_err(|_| ResourceUnavailable("invalid storage response").into())
        }
    }
    pub async fn list(&self, value: &str) -> Result<Vec<Entry>> {
        let value_path = path(value)?;
        let value = self
            .request(
                Method::GET,
                self.url("dir", Some(&self.remote(value)?), false)?,
                None,
            )
            .await?;
        let entries = if self.options.seafile_repo_token {
            value.get("dirent_list").and_then(Value::as_array)
        } else {
            value.as_array()
        }
        .context(ResourceUnavailable("Invalid Seafile directory response"))?;
        ensure!(
            entries.len() <= 500_000,
            ResourceUnavailable("Invalid Seafile directory response")
        );
        let mut names = HashSet::new();
        entries
            .iter()
            .map(|item| {
                let name = string(item, "name")?;
                ensure!(
                    safe_segment(&name)
                        && !name.chars().any(char::is_control)
                        && names.insert(name.clone()),
                    "Invalid or duplicate Seafile entry"
                );
                let directory = match string(item, "type")?.as_str() {
                    "dir" => true,
                    "file" => false,
                    _ => return Err(ResourceUnavailable("Unsupported Seafile entry type").into()),
                };
                let modified = long(item, "mtime")
                    .unwrap_or(0)
                    .checked_mul(1000)
                    .context(ResourceUnavailable("invalid Seafile modification time"))?;
                Ok(Entry {
                    name: name.clone(),
                    path: format!("{}/{}", value_path.trim_end_matches('/'), name),
                    is_directory: directory,
                    size: if directory {
                        -1
                    } else {
                        long(item, "size").unwrap_or(-1)
                    },
                    created_date: 0,
                    updated_date: modified,
                    is_hidden: name.starts_with('.'),
                    is_symbolic_link: false,
                    is_symbolic_link_known: true,
                    reference: None,
                })
            })
            .collect()
    }
    pub async fn stat(&self, value: &str, reference: Option<&Value>) -> Result<Entry> {
        if path(value)? == "/" {
            self.list("/").await?;
            return Ok(Entry {
                name: "/".into(),
                path: "/".into(),
                is_directory: true,
                size: -1,
                created_date: 0,
                updated_date: 0,
                is_hidden: false,
                is_symbolic_link: false,
                is_symbolic_link_known: false,
                reference: None,
            });
        }
        let (parent, name) = value.rsplit_once('/').unwrap_or(("/", value));
        let entries = self
            .list(if parent.is_empty() { "/" } else { parent })
            .await?;
        let id = reference
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut entries = entries
            .into_iter()
            .filter(|e| id.is_empty() && e.name == name);
        let selected = entries
            .next()
            .ok_or_else(|| anyhow::Error::new(Missing).context(PlatformFailure))?;
        ensure!(
            entries.next().is_none(),
            ResourceUnavailable("storage entry path is ambiguous")
        );
        Ok(selected)
    }
    fn transfer_url(&self, value: &str) -> Result<Url> {
        let target = Url::parse(value)?;
        let server = Url::parse(&self.server)?;
        ensure!(
            matches!(target.scheme(), "http" | "https")
                && target.host_str() == server.host_str()
                && (target.scheme() == "https" || server.scheme() == "http")
                && target.username().is_empty()
                && target.password().is_none_or(str::is_empty)
                && target.fragment().is_none_or(str::is_empty),
            "Seafile transfer URL leaves the configured server"
        );
        Ok(target)
    }
    pub async fn download(
        &self,
        value: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let link = self
            .request(
                Method::GET,
                self.url(
                    if self.options.seafile_repo_token {
                        "download-link"
                    } else {
                        "file"
                    },
                    Some(&self.remote(value)?),
                    false,
                )?,
                None,
            )
            .await?;
        let target = self.transfer_url(link.as_str().context("invalid Seafile transfer URL")?)?;
        crate::storage::http::read_file(
            &self.client,
            target,
            size,
            reqwest::header::HeaderMap::new(),
            output,
        )
        .await
    }
    pub async fn upload(
        &self,
        value: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<bool> {
        ensure!(
            self.writable(),
            ResourceUnavailable("Seafile account is read-only")
        );
        ensure!(size >= 0, "Seafile upload requires a known size");
        let value = path(value)?;
        ensure!(value != "/", "Seafile root cannot be overwritten");
        let (parent, name) = value
            .rsplit_once('/')
            .context("invalid Seafile upload path")?;
        let parent = if parent.is_empty() { "/" } else { parent };
        let link = self
            .request(
                Method::GET,
                self.url("upload-link", Some(&self.remote(parent)?), false)?,
                None,
            )
            .await?;
        let mut target = self.transfer_url(link.as_str().context("invalid Seafile upload URL")?)?;
        target.query_pairs_mut().append_pair("ret-json", "1");
        let boundary = format!(
            "folderspan{}",
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 18]>())
        );
        let field = |key: &str, value: &str| {
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
            )
        };
        let filename = name.replace('\\', "\\\\").replace('"', "\\\"");
        let prefix=format!("{}{}--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            field("parent_dir",&self.remote(parent)?),field("replace","1")).into_bytes();
        let suffix = format!("\r\n--{boundary}--\r\n").into_bytes();
        let length = size
            .checked_add(prefix.len() as i64)
            .and_then(|n| n.checked_add(suffix.len() as i64))
            .context("Storage upload requires a valid size")?;
        let count = consumed.clone();
        let ended = Arc::new(AtomicBool::new(false));
        let stream_ended = ended.clone();
        let stream = futures_util::stream::try_unfold(
            (input, 0u64, Some(prefix), Some(suffix)),
            move |(mut input, sent, prefix, suffix)| {
                let count = count.clone();
                let stream_ended = stream_ended.clone();
                async move {
                    if let Some(prefix) = prefix {
                        return Ok::<_, std::io::Error>(Some((
                            prefix,
                            (input, sent, None, suffix),
                        )));
                    }
                    match input.recv().await {
                        Some(bytes) => {
                            let next = sent
                                .checked_add(bytes.len() as u64)
                                .ok_or_else(|| std::io::Error::other("upload size overflow"))?;
                            if next > size as u64 {
                                return Err(std::io::Error::other("upload length exceeded"));
                            }
                            count.store(next, Ordering::Release);
                            Ok(Some((bytes, (input, next, None, suffix))))
                        }
                        None if sent != size as u64 => {
                            Err(std::io::Error::other("upload ended early"))
                        }
                        None => {
                            stream_ended.store(true, Ordering::Release);
                            Ok(suffix.map(|suffix| (suffix, (input, sent, None, None))))
                        }
                    }
                }
            },
        );
        let response = self
            .client
            .post(target)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("Content-Length", length.to_string())
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        let response = success(response)?;
        ensure!(
            ended.load(Ordering::Acquire),
            ResourceUnavailable("upload ended before browser finish")
        );
        let response = text(response).await?;
        let response: Value = serde_json::from_str(&response)
            .map_err(|_| ResourceUnavailable("invalid storage response"))?;
        let files = response.as_array().context(ResourceUnavailable(
            "Seafile upload returned no file metadata",
        ))?;
        ensure!(
            files.len() == 1
                && string(&files[0], "name")? == name
                && long(&files[0], "size") == Some(size),
            ResourceUnavailable("Seafile did not save the selected file")
        );
        Ok(true)
    }
    pub async fn mutate(&self, op: &str, value: &str, to: &str, directory: bool) -> Result<bool> {
        ensure!(
            self.writable(),
            ResourceUnavailable("Seafile account is read-only")
        );
        ensure!(
            !matches!(op, "/copy" | "/delete-empty-directory"),
            PlatformFailure
        );
        let source = path(value)?;
        ensure!(source != "/", "Seafile root cannot be changed");
        if op == "/create" {
            let (sender, input) = mpsc::channel(1);
            drop(sender);
            return self
                .upload(&source, 0, input, Arc::new(AtomicU64::new(0)))
                .await;
        }
        let mut form = None;
        let mut is_directory = directory;
        if matches!(op, "/rename" | "/move") {
            let dest = path(to)?;
            ensure!(dest != "/", "Seafile root cannot be renamed");
            if op == "/move" {
                ensure!(
                    source != dest && !dest.starts_with(&format!("{source}/")),
                    "invalid move destination"
                );
                match self.stat(&dest, None).await {
                    Ok(_) => return Err(ResourceUnavailable("Move target already exists").into()),
                    Err(e) => ensure!(
                        e.is::<Missing>(),
                        ResourceUnavailable("Cannot verify that the move target is absent")
                    ),
                }
            }
            ensure!(
                source.rsplit_once('/').map(|v| v.0) == dest.rsplit_once('/').map(|v| v.0),
                "Use file tasks to move Seafile items between directories"
            );
            let entry = self.stat(&source, None).await?;
            is_directory = entry.is_directory;
            let (parent, name) = dest
                .rsplit_once('/')
                .context("invalid Seafile rename target")?;
            ensure!(
                self.list(if parent.is_empty() { "/" } else { parent })
                    .await?
                    .iter()
                    .all(|e| e.name != name || e.path == source),
                ResourceUnavailable("Seafile rename destination already exists")
            );
            form = Some(vec![
                ("operation", "rename".into()),
                ("newname", name.into()),
            ]);
        } else if op == "/mkdir" {
            let (parent, name) = source
                .rsplit_once('/')
                .context("invalid Seafile directory")?;
            ensure!(
                self.list(if parent.is_empty() { "/" } else { parent })
                    .await?
                    .iter()
                    .all(|e| e.name != name),
                ResourceUnavailable("Seafile destination already exists")
            );
            form = Some(vec![("operation", "mkdir".into())]);
            is_directory = true;
        } else {
            ensure!(op == "/delete", "invalid Seafile operation");
        }
        let remote = self.remote(&source)?;
        self.request(
            if op == "/delete" {
                Method::DELETE
            } else {
                Method::POST
            },
            self.url(
                if is_directory { "dir" } else { "file" },
                Some(&remote),
                !is_directory,
            )?,
            form.as_deref(),
        )
        .await?;
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seafile_namespace_and_transfer_authority_are_checked_without_credentials() {
        assert!(library("00000000-0000-0000-0000-000000000001"));
        for id in ["", "libA", "00000000-0000-0000-0000-00000000000g"] {
            assert!(!library(id));
        }
        assert_eq!(path("/中文 file ").unwrap(), "/中文 file ");
        for p in ["/../escape", "/nested//file", "relative", "/a\nb"] {
            assert!(path(p).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        let seafile = Seafile::new(
            "https://cloud.test/base",
            &json!({"cloud":{"libraryId":"00000000-0000-0000-0000-000000000001"}}),
            store,
        )
        .unwrap();
        assert!(
            seafile
                .transfer_url("https://cloud.test:8082/upload?ticket=private")
                .is_ok()
        );
        for url in [
            "http://cloud.test/upload",
            "https://other.test/upload",
            "https://user@cloud.test/upload",
            "https://cloud.test/upload#fragment",
        ] {
            assert!(seafile.transfer_url(url).is_err());
        }
    }
}
