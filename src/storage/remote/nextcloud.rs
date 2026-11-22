mod advanced;
mod metadata;
use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::{
        accounts::{Credential, Kind, Storage, canonical_server},
        http::{HttpStatus, checked_path, success, text},
        remote::{DownloadPart, Entry, http_directory::client, safe_segment, webdav::WebDav},
    },
};
use anyhow::{Result, ensure};
pub(crate) use metadata::BATCH_SIZE as METADATA_BATCH_SIZE;
use reqwest::{Client, Method, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, atomic::AtomicU64};
use tokio::sync::mpsc;
use url::Url;

const PROPFIND: &str = r#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/><oc:permissions/><d:displayname/><d:getcontentlength/><d:resourcetype/><d:getlastmodified/></d:prop></d:propfind>"#;
#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Options {
    account_id: String,
    connection_id: String,
    library_id: String,
    root_id: String,
    read_only: bool,
}
#[derive(Clone)]
pub struct Nextcloud {
    host: String,
    separator: String,
    options: Options,
    store: Arc<Storage>,
    client: Client,
}
pub(crate) fn reference(value: Option<&Value>, key: &str) -> Result<String> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    ensure!(value.is_object(), "invalid storage reference");
    match value.get(key) {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(anyhow::anyhow!("invalid storage reference")),
    }
}
pub(crate) fn xml(value: &str) -> Result<roxmltree::Document<'_>> {
    ensure!(
        !value.to_ascii_uppercase().contains("<!DOCTYPE")
            && !value.to_ascii_uppercase().contains("<!ENTITY"),
        "invalid Nextcloud XML"
    );
    Ok(roxmltree::Document::parse_with_options(
        value,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 200_000,
            ..Default::default()
        },
    )?)
}
pub(crate) fn tag<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(str::trim)
}
pub(crate) fn successful<'a>(node: roxmltree::Node<'a, 'a>) -> Vec<roxmltree::Node<'a, 'a>> {
    node.descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "propstat"
                && tag(*n, "status").is_some_and(|s| s.contains(" 200 "))
        })
        .collect()
}
pub(crate) fn property<'a>(nodes: &[roxmltree::Node<'a, 'a>], name: &str) -> Option<&'a str> {
    nodes.iter().find_map(|n| tag(*n, name))
}
pub(crate) fn file_id(node: roxmltree::Node<'_, '_>) -> Result<String> {
    let properties = successful(node);
    let id = property(&properties, "fileid").unwrap_or("");
    ensure!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
        "Nextcloud did not expose a stable file ID"
    );
    Ok(id.into())
}
pub(crate) fn http_date(value: Option<&str>) -> i64 {
    value
        .and_then(|s| chrono::DateTime::parse_from_rfc2822(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}
pub(crate) struct Metadata {
    pub id: String,
    pub directory: bool,
    pub size: i64,
    pub modified: i64,
    pub permissions: String,
}
impl Nextcloud {
    pub fn new(host: &str, separator: &str, extras: &Value, store: Arc<Storage>) -> Result<Self> {
        Ok(Self {
            host: host.into(),
            separator: separator.into(),
            options: serde_json::from_value(extras.get("cloud").cloned().unwrap_or(json!({})))?,
            store,
            client: client()?,
        })
    }
    pub fn capabilities(&self) -> Value {
        let account = self
            .store
            .metadata(&self.options.account_id)
            .ok()
            .filter(|a| {
                a.kind == Kind::Nextcloud && !a.requires_authorization && !a.access_token.is_empty()
            });
        let read = account.is_some();
        let write = account.is_some_and(|a| !a.read_only && !self.options.read_only);
        json!({"read":read,"write":write,"delete":write,"rename":write,"sync":true})
    }
    pub fn writable(&self) -> bool {
        self.capabilities()["write"] == true
    }
    pub(crate) fn account(&self) -> Result<Credential> {
        let a = self
            .store
            .credential("Nextcloud", &self.host, &self.options.account_id, "")?;
        ensure!(
            a.kind == Kind::Nextcloud && a.server == canonical_server(&self.host)?,
            ResourceUnavailable("Nextcloud account belongs to another server")
        );
        ensure!(
            safe_segment(&a.provider_account_id),
            "invalid Nextcloud user ID"
        );
        Ok(a)
    }
    fn root(&self) -> Result<&str> {
        let root = if self.options.root_id.trim().is_empty() {
            "/"
        } else {
            &self.options.root_id
        };
        checked_path(root)?;
        Ok(root.trim_end_matches('/'))
    }
    fn remote(&self, path: &str) -> Result<String> {
        checked_path(path)?;
        Ok(format!("{}{path}", self.root()?))
    }
    pub(crate) fn url(account: &Credential, parts: &[&str]) -> Result<Url> {
        let mut u = Url::parse(&account.server)?;
        {
            let mut segments = u
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("invalid storage server"))?;
            segments.pop_if_empty();
            for part in parts {
                ensure!(safe_segment(part), "invalid cloud URL segment");
                segments.push(part);
            }
        }
        Ok(u)
    }
    fn file_url(&self, a: &Credential, path: &str) -> Result<Url> {
        let remote = self.remote(path)?;
        let mut parts = vec!["remote.php", "dav", "files", a.provider_account_id.as_str()];
        parts.extend(
            remote
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty()),
        );
        Self::url(a, &parts)
    }
    fn delegate(&self, a: &Credential) -> Result<WebDav> {
        let root = self.file_url(a, "/")?;
        WebDav::nextcloud(
            root.as_str(),
            &a.username,
            &a.access_token,
            &self.separator,
            self.client.clone(),
        )
    }
    async fn verified_delegate(
        &self,
        a: &Credential,
        path: &str,
        r: Option<&Value>,
    ) -> Result<WebDav> {
        let delegate = self.delegate(a)?;
        let normalized = delegate.normalize(path)?;
        // Legacy DAV trims names; verify the path actually used before applying a stable ID.
        if normalized != path && !reference(r, "id")?.trim().is_empty() {
            self.metadata(&normalized, r).await?;
        }
        Ok(delegate)
    }
    pub(crate) async fn request(
        &self,
        a: &Credential,
        method: Method,
        url: Url,
        depth: Option<&str>,
    ) -> Result<Response> {
        let mut r = self
            .client
            .request(method, url)
            .basic_auth(&a.username, Some(&a.access_token))
            .header("OCS-APIRequest", "true");
        if let Some(depth) = depth {
            r = r
                .header("Depth", depth)
                .header("Content-Type", "application/xml")
                .body(PROPFIND);
        }
        success(r.send().await.map_err(|_| PlatformFailure)?)
    }
    async fn bare_metadata(&self, path: &str, id: Option<&str>) -> Result<Metadata> {
        let account = self.account()?;
        let url = self.file_url(&account, path)?;
        let body = text(
            self.request(&account, Method::from_bytes(b"PROPFIND")?, url, Some("0"))
                .await?,
        )
        .await?;
        let doc = xml(&body)?;
        let props = successful(doc.root());
        let selected = file_id(doc.root())?;
        ensure!(
            id.is_none_or(|id| id.is_empty() || id == selected),
            "Nextcloud file identity changed"
        );
        let directory = props.iter().any(|p| {
            p.descendants()
                .any(|n| n.is_element() && n.tag_name().name() == "collection")
        });
        let size = if directory {
            -1
        } else {
            property(&props, "getcontentlength")
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1)
        };
        let modified = http_date(property(&props, "getlastmodified"));
        Ok(Metadata {
            id: selected,
            directory,
            size,
            modified,
            permissions: property(&props, "permissions").unwrap_or("").into(),
        })
    }
    pub(crate) async fn validate_container(&self, path: &str, r: Option<&Value>) -> Result<()> {
        let ancestor = reference(r, "ancestorId")?;
        if !ancestor.trim().is_empty() {
            let parent = reference(r, "ancestorPath")?;
            ensure!(
                !parent.trim().is_empty()
                    && (path == parent
                        || path.starts_with(&format!("{}/", parent.trim_end_matches('/')))),
                "Nextcloud path is outside its selected ancestor"
            );
            self.bare_metadata(&parent, Some(&ancestor)).await?;
        }
        let parent = reference(r, "parentId")?;
        if !parent.trim().is_empty() {
            let path = path
                .trim_end_matches('/')
                .rsplit_once('/')
                .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                .unwrap_or("/");
            self.bare_metadata(path, Some(&parent)).await?;
        }
        Ok(())
    }
    pub(crate) async fn metadata(&self, path: &str, r: Option<&Value>) -> Result<Metadata> {
        self.validate_container(path, r).await?;
        self.bare_metadata(path, Some(&reference(r, "id")?)).await
    }
    async fn validate(&self, path: &str, r: Option<&Value>) -> Result<()> {
        if reference(r, "id")?.trim().is_empty() {
            self.validate_container(path, r).await
        } else {
            self.metadata(path, r).await.map(|_| ())
        }
    }

    pub(crate) async fn content_manifest_exists(&self) -> Result<bool> {
        let account = self.account()?;
        let target = self.file_url(&account, "/.folderspan-content.json")?;
        let response = self
            .client
            .get(target)
            .basic_auth(&account.username, Some(&account.access_token))
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let response = success(response)?;
        let revision = response
            .headers()
            .get("etag")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        ensure!(
            revision.starts_with('"') && revision.ends_with('"') && !revision.starts_with("W/"),
            "Nextcloud content manifest requires a strong revision"
        );
        crate::storage::http::body(response, 4 * 1024 * 1024).await?;
        Ok(true)
    }
    pub async fn list(&self, path: &str, r: Option<&Value>) -> Result<Vec<Entry>> {
        self.validate(path, r).await?;
        let a = self.account()?;
        let body = text(
            self.request(
                &a,
                Method::from_bytes(b"PROPFIND")?,
                self.file_url(&a, path)?,
                Some("1"),
            )
            .await?,
        )
        .await?;
        self.delegate(&a)?.parse(&body, path)
    }
    pub async fn stat(&self, path: &str, r: Option<&Value>) -> Result<Entry> {
        let m = self.metadata(path, r).await?;
        Ok(Entry {
            name: path
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("")
                .into(),
            path: path.into(),
            is_directory: m.directory,
            size: m.size,
            created_date: 0,
            updated_date: m.modified,
            is_hidden: false,
            is_symbolic_link: false,
            is_symbolic_link_known: false,
            reference: Some(json!({"id":m.id})),
        })
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
        r: Option<&Value>,
    ) -> Result<()> {
        self.validate(path, r).await?;
        self.verified_delegate(&self.account()?, path, r)
            .await?
            .download(path, size, output)
            .await
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
        r: Option<&Value>,
    ) -> Result<bool> {
        ensure!(
            self.writable(),
            ResourceUnavailable("Nextcloud account is read-only")
        );
        self.validate(path, r).await?;
        self.verified_delegate(&self.account()?, path, r)
            .await?
            .upload(path, size, input, consumed)
            .await
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        to: &str,
        directory: bool,
        r: Option<&Value>,
        target: Option<&Value>,
    ) -> Result<bool> {
        ensure!(
            self.writable(),
            ResourceUnavailable("Nextcloud account is read-only")
        );
        ensure!(operation != "/delete-empty-directory", PlatformFailure);
        self.validate(path, r).await?;
        if operation == "/copy" {
            self.validate(to, target).await?;
        }
        if operation == "/move" {
            checked_path(path)?;
            checked_path(to)?;
            let source = path.trim_end_matches('/');
            let dest = to.trim_end_matches('/');
            ensure!(
                !source.is_empty()
                    && !dest.is_empty()
                    && source != dest
                    && !dest.starts_with(&format!("{source}/")),
                "invalid move destination"
            );
            match self.metadata(to, target).await {
                Ok(_) => return Err(ResourceUnavailable("Move target already exists").into()),
                Err(e) => ensure!(
                    e.downcast_ref::<HttpStatus>().is_some_and(|s| s.0 == 404),
                    ResourceUnavailable("Cannot verify that the move target is absent")
                ),
            }
        }
        let a = self.account()?;
        let delegate = self.verified_delegate(&a, path, r).await?;
        if matches!(operation, "/copy" | "/move") {
            self.verified_delegate(&a, to, target).await?;
        }
        delegate.mutate(operation, path, to, directory).await
    }
}

#[cfg(test)]
mod content_manifest_tests {
    use super::*;
    use axum::{
        Router,
        extract::{Request, State},
        http::StatusCode,
        response::IntoResponse,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    async fn route(
        State(mode): State<Arc<AtomicUsize>>,
        request: Request,
    ) -> axum::response::Response {
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.uri().path(),
            "/remote.php/dav/files/alice/selected/.folderspan-content.json"
        );
        use base64::Engine as _;
        assert_eq!(
            request.headers()["authorization"],
            "Basic ".to_owned()
                + &base64::engine::general_purpose::STANDARD.encode(b"alice:private-test-token")
        );
        match mode.load(Ordering::SeqCst) {
            0 => StatusCode::NOT_FOUND.into_response(),
            1 => ([("etag", "\"revision\"")], b"{}".to_vec()).into_response(),
            2 => ([("etag", "W/\"revision\"")], b"{}".to_vec()).into_response(),
            3 => ([("etag", "\"revision\"")], vec![b'x'; 4 * 1024 * 1024 + 1]).into_response(),
            4 => StatusCode::FORBIDDEN.into_response(),
            5 => ([("etag", "\"revision\"")], Vec::<u8>::new()).into_response(),
            6 => {
                let chunks = futures_util::stream::iter(
                    (0..65).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 64 * 1024])),
                );
                (
                    [("etag", "\"revision\"")],
                    axum::body::Body::from_stream(chunks),
                )
                    .into_response()
            }
            _ => (StatusCode::OK, b"{}".to_vec()).into_response(),
        }
    }
    #[tokio::test]
    async fn legacy_manifest_reads_configured_root_without_directory_listing() {
        let root = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicUsize::new(0));
        let app = Router::new().fallback(route).with_state(mode.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let id = "account_for_manifest_test";
        std::fs::write(root.path().join("storage-accounts.json"),serde_json::to_vec(&json!({
            "version":1,"accounts":{id:{"id":id,"kind":"Nextcloud","providerAccountId":"alice","label":"Alice",
            "username":"alice","server":host,"accessToken":"private-test-token"}},"generations":{}
        })).unwrap()).unwrap();
        let store = Storage::load(root.path()).unwrap();
        let client = Nextcloud::new(
            &host,
            "/",
            &json!({"cloud":{"accountId":id,"rootId":"/selected","connectionId":"manifest"}}),
            store.clone(),
        )
        .unwrap();
        assert!(!client.content_manifest_exists().await.unwrap());
        for number in [1, 5] {
            mode.store(number, Ordering::SeqCst);
            assert!(client.content_manifest_exists().await.unwrap());
        }
        for (number, status) in [(2, 400), (3, 409), (4, 500), (6, 409), (7, 400)] {
            mode.store(number, Ordering::SeqCst);
            assert_eq!(
                crate::management::reply::Reply::from_error(
                    client.content_manifest_exists().await.unwrap_err()
                )
                .status,
                status
            );
        }
        server.abort();
        let _ = server.await;
        store.finish_cleanup().await;
    }
}
