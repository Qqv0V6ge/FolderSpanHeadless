pub(crate) mod advanced;
#[cfg(feature = "pro")]
#[rustfmt::skip]
#[path = "../../pro/src/storage/remote/cloud.rs"]
pub mod cloud;
pub(crate) mod content;
pub mod ftp;
pub mod http_directory;
pub mod nextcloud;
pub mod nfs;
#[cfg(feature = "pro")]
#[rustfmt::skip]
#[path = "../../pro/src/storage/remote/resumable.rs"]
mod resumable;
pub mod s3;
pub mod seafile;
pub mod sftp;
pub mod smb;
pub(crate) mod upload_state;
pub mod webdav;

#[cfg(feature = "pro")]
use self::cloud::Cloud;
use self::{
    ftp::Ftp, http_directory::HttpDirectory, nextcloud::Nextcloud, nfs::Nfs, s3::S3,
    seafile::Seafile, sftp::Sftp, smb::Smb, webdav::WebDav,
};
use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
        wire::BODY_LIMIT,
    },
    storage::accounts::Storage,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    protocol: String,
    host: String,
    username: String,
    password: String,
    #[serde(default, rename = "pathSeparator")]
    separator: String,
    #[serde(default, rename = "extras")]
    extras: Value,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(Value::String(token)) = self
            .extras
            .get_mut("s3")
            .and_then(|v| v.get_mut("sessionToken"))
        {
            token.zeroize();
        }
        if let Some(Value::String(key)) = self
            .extras
            .get_mut("sftp")
            .and_then(|v| v.get_mut("privateKey"))
        {
            key.zeroize();
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    callback_id: String,
    config: Config,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PathInput {
    handle: String,
    path: String,
    #[serde(default = "unknown_size")]
    size: i64,
    #[serde(default)]
    reference: Option<Value>,
    #[serde(default, rename = "newPath")]
    new_path: String,
    #[serde(default, rename = "newReference")]
    new_reference: Option<Value>,
    #[serde(default, rename = "isDirectory")]
    is_directory: bool,
}
pub(crate) fn validate_reference(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    ensure!(value.is_object(), "invalid storage reference");
    ensure!(
        value.as_object().unwrap().keys().all(|k| [
            "id",
            "parentId",
            "ancestorId",
            "ancestorPath",
            "content"
        ]
        .contains(&k.as_str())),
        "unknown storage reference field"
    );
    for key in ["id", "parentId", "ancestorId", "ancestorPath"] {
        ensure!(
            value.get(key).is_none_or(Value::is_string),
            "invalid storage reference"
        );
    }
    if let Some(content) = value.get("content").filter(|v| !v.is_null()) {
        ensure!(
            content.as_object().is_some_and(|o| o.keys().all(|k| [
                "vaultId",
                "entryId",
                "revisionId",
                "ordinaryPath"
            ]
            .contains(&k.as_str()))),
            "unknown content reference field"
        );
        ensure!(
            content.is_object()
                && ["vaultId", "entryId"]
                    .iter()
                    .all(|k| content.get(*k).is_some_and(Value::is_string)),
            "invalid content reference"
        );
        for key in ["revisionId", "ordinaryPath"] {
            ensure!(
                content.get(key).is_none_or(Value::is_string),
                "invalid content reference"
            );
        }
    }
    Ok(())
}
pub(crate) fn reference_defaults(value: &Value) -> Value {
    if value.is_null() {
        return Value::Null;
    }
    let mut result = value.clone();
    for key in ["id", "parentId", "ancestorId", "ancestorPath"] {
        if result.get(key).is_none() {
            result[key] = json!("");
        }
    }
    if result.get("content").is_none() {
        result["content"] = Value::Null;
    }
    if result["content"].is_object() {
        for key in ["revisionId", "ordinaryPath"] {
            if result["content"].get(key).is_none() {
                result["content"][key] = json!("");
            }
        }
    }
    result
}
pub(crate) fn deserialize_reference<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    validate_reference(value.as_ref()).map_err(serde::de::Error::custom)?;
    Ok(value.as_ref().map(reference_defaults))
}
pub(crate) fn serialize_reference<S: serde::Serializer>(
    value: &Option<Value>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    value.as_ref().map(reference_defaults).serialize(serializer)
}
fn unknown_size() -> i64 {
    -1
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub created_date: i64,
    #[serde(default)]
    pub updated_date: i64,
    #[serde(default)]
    pub is_hidden: bool,
    #[serde(default)]
    pub is_symbolic_link: bool,
    #[serde(default)]
    pub is_symbolic_link_known: bool,
    #[serde(
        default,
        serialize_with = "serialize_reference",
        deserialize_with = "deserialize_reference"
    )]
    pub reference: Option<Value>,
}
#[derive(Clone)]
enum Client {
    Seafile(Seafile),
    Nextcloud(Nextcloud),
    #[cfg(feature = "pro")]
    OfficialCloud(Cloud),
    Sftp(Sftp),
    S3(S3),
    Nfs(Nfs),
    Smb(Smb),
    Ftp(Ftp),
    Http(HttpDirectory),
    WebDav(WebDav),
}
impl Client {
    fn create(
        config: &Config,
        store: Option<&Arc<Storage>>,
        session: &Arc<Session>,
        callback: &str,
    ) -> Result<Self> {
        Ok(match config.protocol.as_str() {
            "Nextcloud" => Client::Nextcloud(Nextcloud::new(
                &config.host,
                &config.separator,
                &config.extras,
                store
                    .context(ResourceUnavailable("storage account service unavailable"))?
                    .clone(),
            )?),
            "Seafile" => Client::Seafile(Seafile::new(
                &config.host,
                &config.extras,
                store
                    .context(ResourceUnavailable("storage account service unavailable"))?
                    .clone(),
            )?),
            #[cfg(feature = "pro")]
            "GoogleDrive" | "Dropbox" => Client::OfficialCloud(Cloud::new(
                &config.protocol,
                &config.extras,
                store
                    .context(ResourceUnavailable("storage account service unavailable"))?
                    .clone(),
            )?),
            #[cfg(not(feature = "pro"))]
            "GoogleDrive" | "Dropbox" => {
                return Err(ResourceUnavailable(
                    "Official storage is available only in the Pro edition",
                )
                .into());
            }
            "NFS" => Client::Nfs(Nfs::new(&config.host, &config.extras)?),
            "SMB" => Client::Smb(Smb::new(
                &config.host,
                &config.username,
                &config.password,
                &config.separator,
                &config.extras,
            )?),
            "S3" => Client::S3(S3::new(
                &config.host,
                &config.username,
                &config.password,
                &config.separator,
                &config.extras,
            )?),
            "SFTP" => Client::Sftp(Sftp::new(
                &config.host,
                &config.username,
                &config.password,
                &config.extras,
                session,
                callback,
            )?),
            "FTP" => Client::Ftp(Ftp::new(
                &config.host,
                &config.username,
                &config.password,
                &config.separator,
                &config.extras,
            )?),
            "HttpDirectory" => Client::Http(HttpDirectory::new(
                &config.host,
                &config.username,
                &config.password,
            )?),
            "WebDav" => Client::WebDav(WebDav::new(
                &config.host,
                &config.username,
                &config.password,
                &config.separator,
                &config.extras,
            )?),
            _ => anyhow::bail!("unknown storage protocol"),
        })
    }

    fn writable(&self) -> bool {
        match self {
            Self::Nextcloud(c) => c.writable(),
            Self::Seafile(c) => c.writable(),
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.writable(),
            Self::Http(_) => false,
            _ => true,
        }
    }
    fn capabilities(&self) -> Value {
        match self {
            Self::Nextcloud(c) => c.capabilities(),
            Self::Seafile(c) => c.capabilities(),
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.capabilities(),
            _ => capabilities(self.writable(), !matches!(self, Self::Nfs(_))),
        }
    }
    fn transfer(&self) -> Result<Self> {
        Ok(match self {
            Self::Nextcloud(c) => Self::Nextcloud(c.clone()),
            Self::Seafile(c) => Self::Seafile(c.clone()),
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => Self::OfficialCloud(c.clone()),
            Self::Http(c) => Self::Http(c.transfer()?),
            Self::S3(c) => Self::S3(c.transfer()?),
            Self::Nfs(c) => Self::Nfs(c.clone()),
            Self::Smb(c) => Self::Smb(c.clone()),
            Self::Ftp(c) => Self::Ftp(c.clone()),
            Self::Sftp(c) => Self::Sftp(c.clone()),
            Self::WebDav(c) => Self::WebDav(c.transfer()?),
        })
    }
    async fn list(&self, path: &str, reference: Option<&Value>) -> Result<Vec<Entry>> {
        match self {
            Self::Nextcloud(c) => c.list(path, reference).await,
            Self::Seafile(c) => c.list(path).await,
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.list(path, reference).await,
            Self::Http(c) => c.list(path).await,
            Self::S3(c) => c.list(path).await,
            Self::Nfs(c) => c.list(path).await,
            Self::Smb(c) => c.list(path).await,
            Self::Ftp(c) => c.list(path).await,
            Self::Sftp(c) => c.list(path).await,
            Self::WebDav(c) => c.list(path).await,
        }
    }
    async fn stat(&self, input: &advanced::Path) -> Result<Entry> {
        #[cfg(feature = "pro")]
        if let Self::OfficialCloud(c) = self {
            return c.stat(&input.path, input.reference.as_ref()).await;
        }
        if let Self::Seafile(c) = self {
            return c.stat(&input.path, input.reference.as_ref()).await;
        }
        if let Self::Nextcloud(c) = self {
            return c.stat(&input.path, input.reference.as_ref()).await;
        }
        let (parent, name) = input
            .path
            .rsplit_once('/')
            .unwrap_or(("/", input.path.as_str()));
        let entries = self
            .list(if parent.is_empty() { "/" } else { parent }, None)
            .await?;
        let id = input
            .reference
            .as_ref()
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut entries = entries.into_iter().filter(|e| {
            if id.is_empty() {
                e.name == name
            } else {
                e.reference
                    .as_ref()
                    .and_then(|r| r.get("id"))
                    .and_then(Value::as_str)
                    == Some(id)
            }
        });
        let entry = entries.next().ok_or(PlatformFailure)?;
        ensure!(
            entries.next().is_none(),
            ResourceUnavailable("storage entry path is ambiguous")
        );
        Ok(entry)
    }
    async fn delete_empty(&self, path: &advanced::Path) -> Result<bool> {
        match self {
            Self::S3(client) => {
                client
                    .mutate("/delete-empty-directory", &path.path, "", true)
                    .await
            }
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
        cancel: &CancellationToken,
        reference: Option<&Value>,
    ) -> Result<()> {
        let operation = async {
            match self {
                Self::Nextcloud(c) => c.download(path, size, output, reference).await,
                Self::Seafile(c) => c.download(path, size, output).await,
                #[cfg(feature = "pro")]
                Self::OfficialCloud(c) => c.download(path, size, output, reference).await,
                Self::Http(c) => c.download(path, size, output).await,
                Self::Ftp(c) => c.download(path, size, output).await,
                Self::Sftp(c) => c.download(path, size, output).await,
                Self::S3(c) => c.download(path, size, output).await,
                Self::Smb(c) => c.download(path, size, output).await,
                Self::WebDav(c) => c.download(path, size, output).await,
                Self::Nfs(c) => c.download(path, size, output, cancel).await,
            }
        };
        if matches!(self, Self::Nfs(_)) {
            operation.await
        } else {
            tokio::select! {
                _=cancel.cancelled()=>Err(ResourceUnavailable("network transfer closed").into()),
                result=operation=>result,
            }
        }
    }
    async fn mutate(
        &self,
        operation: &str,
        path: &str,
        destination: &str,
        directory: bool,
        reference: Option<&Value>,
        new_reference: Option<&Value>,
    ) -> Result<bool> {
        match self {
            Self::Seafile(c) => c.mutate(operation, path, destination, directory).await,
            Self::Nextcloud(c) => {
                c.mutate(
                    operation,
                    path,
                    destination,
                    directory,
                    reference,
                    new_reference,
                )
                .await
            }
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => {
                c.mutate(
                    operation,
                    path,
                    destination,
                    directory,
                    reference,
                    new_reference,
                )
                .await
            }
            Self::WebDav(c) => c.mutate(operation, path, destination, directory).await,
            Self::S3(c) => c.mutate(operation, path, destination, directory).await,
            Self::Nfs(c) => c.mutate(operation, path, destination, directory).await,
            Self::Smb(c) => c.mutate(operation, path, destination, directory).await,
            Self::Ftp(c) => c.mutate(operation, path, destination, directory).await,
            Self::Sftp(c) => c.mutate(operation, path, destination, directory).await,
            Self::Http(_) => Err(ResourceUnavailable("storage operation is not permitted").into()),
        }
    }
    async fn upload(
        &self,
        path: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
        cancel: &CancellationToken,
        reference: Option<&Value>,
    ) -> Result<bool> {
        let operation = async {
            match self {
                Self::Nextcloud(c) => c.upload(path, size, input, consumed, reference).await,
                Self::Seafile(c) => c.upload(path, size, input, consumed).await,
                #[cfg(feature = "pro")]
                Self::OfficialCloud(c) => c.upload(path, size, input, consumed, reference).await,
                Self::S3(c) => c.upload(path, size, input, consumed, cancel).await,
                Self::Nfs(c) => c.upload(path, size, input, consumed, cancel).await,
                Self::Smb(c) => c.upload(path, size, input, consumed).await,
                Self::WebDav(c) => c.upload(path, size, input, consumed).await,
                Self::Ftp(c) => c.upload(path, size, input, consumed).await,
                Self::Sftp(c) => c.upload(path, size, input, consumed).await,
                Self::Http(_) => {
                    Err(ResourceUnavailable("storage operation is not permitted").into())
                }
            }
        };
        if matches!(self, Self::S3(_) | Self::Nfs(_)) {
            operation.await
        } else {
            tokio::select! {
                _ = cancel.cancelled() => Err(ResourceUnavailable("network transfer closed").into()),
                result = operation => result,
            }
        }
    }
}
struct Network {
    #[cfg(feature = "pro")]
    identity: String,
    client: Client,
    cancel: CancellationToken,
}
impl Network {
    async fn list(&self, path: &str, reference: Option<&Value>) -> Result<Vec<Entry>> {
        tokio::select! {_=self.cancel.cancelled()=>Err(ResourceUnavailable("network connection closed").into()),result=self.client.list(path,reference)=>result}
    }
}
struct Directory {
    entries: std::vec::IntoIter<Entry>,
}
pub type DownloadPart = Result<(Vec<u8>, i64)>;
struct Download {
    output: AsyncMutex<mpsc::Receiver<DownloadPart>>,
    cancel: CancellationToken,
}
struct Upload {
    input: AsyncMutex<UploadInput>,
    result: watch::Receiver<Option<Arc<Reply>>>,
    cancel: CancellationToken,
    size: i64,
}
struct UploadInput {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    accepted: u64,
}
fn capabilities(writable: bool, sync: bool) -> Value {
    json!({"read":true,"write":writable,"delete":writable,"rename":writable,"sync":sync})
}
pub async fn handle(
    store: Option<&Arc<Storage>>,
    method: &str,
    raw: &str,
    mut body: Vec<u8>,
    session: &Arc<Session>,
) -> Result<Reply> {
    ensure!(body.len() <= BODY_LIMIT, "network message too large");
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let operation = path
        .strip_prefix("/api/web-ui/platform/networks")
        .context("invalid network route")?;
    let query = crate::management::wire::query(query);
    if let Some(operation) = operation.strip_prefix("/advanced/") {
        return advanced::handle(store, method, operation, &query, &body, session).await;
    }
    if method == "POST" && operation.is_empty() {
        let parsed = serde_json::from_slice::<Open>(&body);
        body.zeroize();
        let input = parsed?;
        ensure!(
            (1..=128).contains(&input.callback_id.encode_utf16().count()),
            "invalid network callback"
        );
        ensure!(
            [
                "FTP",
                "SFTP",
                "SMB",
                "WebDav",
                "S3",
                "HttpDirectory",
                "NFS",
                "GoogleDrive",
                "Dropbox",
                "Nextcloud",
                "Seafile"
            ]
            .contains(&input.config.protocol.as_str()),
            "unknown storage protocol"
        );
        let client = Client::create(&input.config, store, session, &input.callback_id)?;
        let cancel = CancellationToken::new();
        let close = cancel.clone();
        let id = session.own_with_close(
            Network {
                #[cfg(feature = "pro")]
                identity: input.config.identity(),
                client,
                cancel,
            },
            move || close.cancel(),
        )?;
        return Ok(Reply::json(json!({"id":id})));
    }
    if method == "GET" && operation == "/directories" {
        let id = query.get("handle").context("directory handle required")?;
        let cursor = session.resource::<Mutex<Directory>>(id)?;
        let mut cursor = cursor.lock().unwrap();
        let entries = cursor.entries.by_ref().take(128).collect::<Vec<_>>();
        let finished = cursor.entries.len() == 0;
        drop(cursor);
        if finished {
            session.release(id);
        }
        return Ok(Reply::json(json!({"entries":entries,"finished":finished})));
    }
    if method == "GET" && operation == "/downloads" {
        let transfer = session
            .resource::<Download>(query.get("handle").context("transfer handle required")?)?;
        let mut output = transfer.output.lock().await;
        let next = tokio::select! {biased;_=transfer.cancel.cancelled()=>return Err(ResourceUnavailable("network transfer closed").into()),next=output.recv()=>next};
        let end = next.is_none();
        let (bytes, total) = next.transpose()?.unwrap_or((vec![], 0));
        let mut reply = Reply::bytes(bytes);
        reply
            .headers
            .insert("x-folderspan-end".into(), end.to_string());
        reply
            .headers
            .insert("x-folderspan-size".into(), total.to_string());
        return Ok(reply);
    }
    if matches!(method, "PUT" | "POST") && operation == "/uploads" {
        let transfer =
            session.resource::<Upload>(query.get("handle").context("transfer handle required")?)?;
        ensure!(
            !transfer.cancel.is_cancelled(),
            ResourceUnavailable("network transfer closed")
        );
        let mut input = transfer.input.lock().await;
        if method == "PUT" {
            if let Some(result) = transfer.result.borrow().as_ref() {
                if result.status != 200 {
                    return Ok((**result).clone());
                }
                return Err(ResourceUnavailable("network upload finished").into());
            }
            let next = input
                .accepted
                .checked_add(body.len() as u64)
                .context("upload size overflow")?;
            if transfer.size >= 0 && next > transfer.size as u64 {
                transfer.cancel.cancel();
                input.sender.take();
                return Err(ResourceUnavailable("upload length exceeded").into());
            }
            let sender = input
                .sender
                .as_ref()
                .context(ResourceUnavailable("network upload finished"))?;
            tokio::select! {
                _ = transfer.cancel.cancelled() => return Err(ResourceUnavailable("network transfer closed").into()),
                result = sender.send(body) => result.map_err(|_| PlatformFailure)?,
            }
            input.accepted = next;
            return Ok(Reply::json(true));
        }
        input.sender.take();
        if transfer.size >= 0 && input.accepted != transfer.size as u64 {
            transfer.cancel.cancel();
            return Err(ResourceUnavailable("upload length mismatch").into());
        }
        drop(input);
        let mut result = transfer.result.clone();
        let finished = tokio::select! {
            biased;
            _ = transfer.cancel.cancelled() => return Err(ResourceUnavailable("network transfer closed").into()),
            result = result.wait_for(Option::is_some) => result.map_err(|_| PlatformFailure)?.as_ref().unwrap().clone(),
        };
        return Ok((*finished).clone());
    }
    if method != "POST" {
        return Ok(Reply::error(404, "not_found", "unknown network operation"));
    }
    let input: PathInput = serde_json::from_slice(&body)?;
    validate_reference(input.reference.as_ref())?;
    validate_reference(input.new_reference.as_ref())?;
    let network = session.resource::<Network>(&input.handle)?;
    ensure!(
        !network.cancel.is_cancelled(),
        ResourceUnavailable("network connection closed")
    );
    if operation == "/capabilities" {
        return Ok(Reply::json(network.client.capabilities()));
    }
    if matches!(
        operation,
        "/mkdir"
            | "/create"
            | "/delete"
            | "/delete-empty-directory"
            | "/rename"
            | "/move"
            | "/copy"
            | "/upload"
    ) && !network.client.writable()
    {
        return Err(ResourceUnavailable("storage operation is not permitted").into());
    }
    if operation == "/upload" {
        let client = network.client.transfer()?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (sender, receiver) = mpsc::channel(1);
        let (result, finished) = watch::channel(None);
        let (start, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let consumed = Arc::new(AtomicU64::new(0));
            let outcome = client
                .upload(
                    &input.path,
                    input.size,
                    receiver,
                    consumed.clone(),
                    &stop,
                    input.reference.as_ref(),
                )
                .await;
            let reply = match outcome {
                Ok(true)
                    if input.size < 0 || consumed.load(Ordering::Acquire) == input.size as u64 =>
                {
                    Reply::json(true)
                }
                Ok(_) => Reply::from_error(
                    ResourceUnavailable("upload ended before all bytes were consumed").into(),
                ),
                Err(error) => Reply::from_error(error),
            };
            result.send_replace(Some(Arc::new(reply)));
        });
        let close = cancel.clone();
        let id = session.own_with_cleanup(
            Upload {
                input: AsyncMutex::new(UploadInput {
                    sender: Some(sender),
                    accepted: 0,
                }),
                result: finished,
                cancel,
                size: input.size,
            },
            move || close.cancel(),
            task,
        )?;
        let _ = start.send(());
        return Ok(Reply::json(json!({"id":id})));
    }
    if matches!(
        operation,
        "/mkdir"
            | "/create"
            | "/delete"
            | "/delete-empty-directory"
            | "/rename"
            | "/move"
            | "/copy"
    ) {
        let result = tokio::select! {
            _ = network.cancel.cancelled() => return Err(ResourceUnavailable("network connection closed").into()),
            result = network.client.mutate(operation, &input.path, &input.new_path, input.is_directory, input.reference.as_ref(), input.new_reference.as_ref()) => result?,
        };
        return Ok(Reply::json(result));
    }
    if operation == "/download" {
        ensure!(
            network.client.capabilities()["read"] == true,
            ResourceUnavailable("storage operation is not permitted")
        );
        let client = network.client.transfer()?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (output, receiver) = mpsc::channel(1);
        let (start, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let result = client
                .download(
                    &input.path,
                    input.size,
                    &output,
                    &stop,
                    input.reference.as_ref(),
                )
                .await;
            if let Err(error) = result {
                let _ = output.send(Err(error)).await;
            }
        });
        let close = cancel.clone();
        let id = session.own_with_cleanup(
            Download {
                output: AsyncMutex::new(receiver),
                cancel,
            },
            move || close.cancel(),
            task,
        )?;
        let _ = start.send(());
        return Ok(Reply::json(json!({"id":id})));
    }
    match operation {
        "/directories" => {
            let entries = network.list(&input.path, input.reference.as_ref()).await?;
            let id = session.own(Mutex::new(Directory {
                entries: entries.into_iter(),
            }))?;
            Ok(Reply::json(json!({"id":id})))
        }
        "/stat" => {
            let path = advanced::Path {
                path: input.path.clone(),
                reference: input.reference.clone(),
            };
            let entry = tokio::select! {
                _=network.cancel.cancelled()=>return Err(ResourceUnavailable("network connection closed").into()),
                result=network.client.stat(&path)=>result?,
            };
            Ok(Reply::json(entry))
        }
        _ => Ok(Reply::error(404, "not_found", "unknown network operation")),
    }
}

pub(crate) fn validate_write_path(path: &str) -> Result<()> {
    let normalized = path.replace('\\', "/");
    let path = normalized.trim_matches('/');
    ensure!(
        path.is_empty() || path.split('/').all(safe_segment),
        "invalid network write path"
    );
    Ok(())
}
pub(crate) fn safe_segment(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && !matches!(trimmed, "." | "..") && !name.contains(['/', '\\', '\0'])
}
pub(crate) fn endpoint(input: &str, default: u16) -> Result<(String, u16)> {
    let input = input.trim();
    ensure!(
        !input.is_empty() && !input.chars().any(char::is_control),
        "invalid remote host"
    );
    let (host, port) = if let Some(ip) = input.strip_prefix('[') {
        let (host, tail) = ip
            .split_once(']')
            .context("invalid bracketed remote host")?;
        let port = if tail.is_empty() {
            default
        } else {
            tail.strip_prefix(':')
                .context("invalid remote port")?
                .parse()?
        };
        (host, port)
    } else if input.matches(':').count() == 1 {
        let (host, port) = input.rsplit_once(':').unwrap();
        (host, port.parse()?)
    } else {
        (input, default)
    };
    ensure!(
        !host.is_empty() && port > 0 && !host.contains(['/', '\\', '@', '?', '#', '[', ']']),
        "invalid remote endpoint"
    );
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    #[test]
    fn reference_schema_matches_strict_pinned_host_decoding() {
        assert!(validate_reference(Some(&json!({"id":"F","parentId":"R"}))).is_ok());
        assert!(validate_reference(Some(&json!({"id":"F","unexpected":1}))).is_err());
        assert!(
            validate_reference(Some(
                &json!({"content":{"vaultId":"v","entryId":"e","unexpected":1}})
            ))
            .is_err()
        );
    }
}
