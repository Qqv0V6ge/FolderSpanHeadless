use super::{Client, Download, Entry, Network, validate_reference};
use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
    },
    storage::{accounts::Storage, remote::DownloadPart},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Path {
    pub path: String,
    #[serde(
        default,
        serialize_with = "super::serialize_reference",
        deserialize_with = "super::deserialize_reference"
    )]
    pub reference: Option<Value>,
}
impl Path {
    pub fn selected(&self, id: &str) -> Self {
        Self {
            path: self.path.clone(),
            reference: Some(json!({"id":id})),
        }
    }
    fn validate(&self) -> Result<()> {
        validate_reference(self.reference.as_ref())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Version {
    pub file: Path,
    pub id: String,
    #[serde(default)]
    pub size: Option<i64>,
    #[serde(default)]
    pub updated_date: Option<i64>,
    #[serde(default)]
    pub connection_binding: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Availability {
    Available,
    PermissionDenied,
    AuthorizationRequired,
    Unsupported,
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Capabilities {
    pub features: BTreeMap<String, Availability>,
    pub upload: Option<Value>,
    pub share_roles: Vec<String>,
    pub share_expiry: bool,
}
impl Capabilities {
    pub fn require(&self, feature: &str) -> Result<()> {
        ensure!(
            self.features.get(feature) == Some(&Availability::Available),
            PlatformFailure
        );
        Ok(())
    }
    pub fn validate_share(&self, request: &ShareRequest) -> Result<()> {
        self.require(if request.kind == ShareKind::Link {
            "CREATE_LINK"
        } else {
            "INVITE_USER"
        })?;
        ensure!(
            self.share_roles.contains(&request.role),
            "unsupported storage sharing role"
        );
        ensure!(
            request.expires_at.is_none() || self.share_expiry,
            "unsupported storage sharing expiry"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ShareKind {
    Link,
    Invitation,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShareRequest {
    pub kind: ShareKind,
    pub role: String,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}
impl ShareRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.role.trim().is_empty()
                && self.role.encode_utf16().count() <= 128
                && !self.role.chars().any(char::is_control),
            "invalid storage sharing role"
        );
        ensure!(
            (self.kind == ShareKind::Invitation)
                == self
                    .recipient
                    .as_ref()
                    .is_some_and(|v| !v.trim().is_empty()),
            "invalid storage sharing recipient"
        );
        ensure!(
            self.recipient.as_ref().is_none_or(
                |v| v.encode_utf16().count() <= 1024 && !v.chars().any(char::is_control)
            ),
            "invalid storage sharing recipient"
        );
        ensure!(
            self.expires_at.is_none_or(|v| v > 0),
            "invalid storage sharing expiry"
        );
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Share {
    pub file: Path,
    pub id: String,
    pub kind: ShareKind,
    pub role: String,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "yes")]
    pub can_revoke: bool,
    #[serde(default)]
    pub connection_binding: String,
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    handle: String,
    #[serde(default)]
    path: Path,
    #[serde(default)]
    cursor: Option<String>,
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    #[serde(default)]
    size: i64,
    #[serde(default)]
    version: Option<Version>,
    #[serde(default)]
    share: Option<Share>,
    #[serde(default)]
    share_request: Option<ShareRequest>,
    #[serde(default)]
    confirmed: bool,
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    #[serde(default)]
    task_key: i64,
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    #[serde(default)]
    upload_reference: Option<Value>,
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    #[serde(default)]
    upload_handle: String,
}
impl Request {
    fn validate(&self) -> Result<()> {
        self.path.validate()?;
        if let Some(v) = &self.version {
            v.file.validate()?;
        }
        if let Some(s) = &self.share {
            s.file.validate()?;
        }
        if let Some(r) = &self.share_request {
            r.validate()?;
        }
        Ok(())
    }
}
impl Client {
    async fn advanced_capabilities(&self, path: &Path) -> Result<Capabilities> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.advanced_capabilities(path).await,
            Self::Nextcloud(c) => c.advanced_capabilities(path).await,
            Self::Seafile(c) => c.advanced_capabilities(path).await,
            _ => Ok(Capabilities::default()),
        }
    }
    async fn read_version(
        &self,
        version: &Version,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.read_version(version, output).await,
            Self::Nextcloud(c) => c.read_version(version, output).await,
            Self::Seafile(c) => c.read_version(version, output).await,
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn versions(&self, path: &Path, cursor: Option<&str>) -> Result<Value> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.versions(path, cursor).await,
            Self::Nextcloud(c) => c.versions(path, cursor).await,
            Self::Seafile(c) => c.versions(path, cursor).await,
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn restore_version(&self, v: &Version, confirmed: bool) -> Result<Entry> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.restore_version(v, confirmed).await,
            Self::Nextcloud(c) => c.restore_version(v, confirmed).await,
            Self::Seafile(c) => c.restore_version(v, confirmed).await,
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn shares(&self, path: &Path, cursor: Option<&str>) -> Result<Value> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.shares(path, cursor).await,
            Self::Nextcloud(c) => c.shares(path, cursor).await,
            Self::Seafile(c) => c.shares(path, cursor).await,
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn create_share(
        &self,
        path: &Path,
        r: &ShareRequest,
        confirmed: bool,
        cancel: &CancellationToken,
    ) -> Result<Share> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.create_share(path, r, confirmed, cancel).await,
            Self::Nextcloud(c) => c.create_share(path, r, confirmed, cancel).await,
            Self::Seafile(c) => c.create_share(path, r, confirmed, cancel).await,
            _ => Err(PlatformFailure.into()),
        }
    }
    async fn revoke_share(&self, share: &Share) -> Result<()> {
        match self {
            #[cfg(feature = "pro")]
            Self::OfficialCloud(c) => c.revoke_share(share).await,
            Self::Nextcloud(c) => c.revoke_share(share).await,
            Self::Seafile(c) => c.revoke_share(share).await,
            _ => Err(PlatformFailure.into()),
        }
    }
}
pub(super) async fn handle(
    store: Option<&Arc<Storage>>,
    method: &str,
    operation: &str,
    _query: &std::collections::HashMap<String, String>,
    body: &[u8],
    session: &Arc<Session>,
) -> Result<Reply> {
    #[cfg(feature = "pro")]
    if method == "PUT" && operation == "upload-chunk" {
        let handle = _query.get("handle").context("upload handle required")?;
        return super::resumable::update(
            session,
            handle,
            operation,
            _query.get("offset").map(String::as_str),
            body,
        )
        .await;
    }
    ensure!(method == "POST", "unsupported storage operation method");
    let input: Request = serde_json::from_slice(body)?;
    input.validate()?;
    #[cfg(feature = "pro")]
    if ["upload-query", "upload-finish", "upload-cancel"].contains(&operation) {
        return super::resumable::update(session, &input.handle, operation, None, &[]).await;
    }
    let network = session.resource::<Network>(&input.handle)?;
    ensure!(
        !network.cancel.is_cancelled(),
        ResourceUnavailable("network connection closed")
    );
    if operation.starts_with("upload-persistence-") {
        let store = store.context(PlatformFailure)?;
        if operation == "upload-persistence-owner" {
            return Ok(Reply::json(store.upload_owner()?));
        }
        #[cfg(not(feature = "pro"))]
        return Err(
            ResourceUnavailable("Resumable uploads are unavailable for this connection").into(),
        );
        #[cfg(feature = "pro")]
        {
            let reference = input
                .upload_reference
                .as_ref()
                .context("upload reference required")?;
            ensure!(
                reference.get("connectionId").and_then(Value::as_str) == Some(&network.identity),
                "upload connection changed"
            );
            return super::resumable::persistence(
                session,
                store,
                &input.handle,
                operation,
                input.task_key,
                reference,
                &input.upload_handle,
            )
            .await;
        }
    }
    if operation == "version-restore" {
        ensure!(input.version.is_some(), "storage version required");
    }
    if operation == "share-create" {
        ensure!(
            input.share_request.is_some(),
            "storage share request required"
        );
    }
    if operation == "share-revoke" {
        ensure!(input.share.is_some(), "storage share required");
    }
    let client = &network.client;
    if operation == "version-read" {
        let version = input.version.context("storage version required")?;
        let client = client.transfer()?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (output, receiver) = mpsc::channel(1);
        let (start, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let result = tokio::select! {
                _=stop.cancelled()=>return,
                result=client.read_version(&version,&output)=>result,
            };
            if let Err(error) = result {
                let _ = output.send(Err(error)).await;
            }
        });
        let close = cancel.clone();
        let id = session.own_with_cleanup(
            Download {
                output: Mutex::new(receiver),
                cancel,
            },
            move || close.cancel(),
            task,
        )?;
        let _ = start.send(());
        return Ok(Reply::json(json!({"id":id})));
    }
    let result = async {
        if operation == "capabilities" {
            return Ok(Reply::json(
                client.advanced_capabilities(&input.path).await?,
            ));
        }
        Ok(match operation {
            "versions" => Reply::json(
                client
                    .versions(&input.path, input.cursor.as_deref())
                    .await?,
            ),
            "version-restore" => Reply::json(
                client
                    .restore_version(
                        input.version.as_ref().context("storage version required")?,
                        input.confirmed,
                    )
                    .await?,
            ),
            "shares" => Reply::json(client.shares(&input.path, input.cursor.as_deref()).await?),
            "share-create" => Reply::json(
                client
                    .create_share(
                        &input.path,
                        input
                            .share_request
                            .as_ref()
                            .context("storage share request required")?,
                        input.confirmed,
                        &network.cancel,
                    )
                    .await?,
            ),
            "share-revoke" => {
                client
                    .revoke_share(input.share.as_ref().context("storage share required")?)
                    .await?;
                Reply::json(json!({}))
            }
            #[cfg(feature = "pro")]
            "upload-start" => {
                super::resumable::start(session, &input.handle, &input.path, input.size).await?
            }
            _ => Reply::error(404, "not_found", "unknown advanced storage operation"),
        })
    };
    tokio::select! {
        _=network.cancel.cancelled()=>Err(ResourceUnavailable("network connection closed").into()),
        result=result=>result,
    }
}
pub(crate) fn validate_upload_reference(v: &Value) -> Result<()> {
    ensure!(v.is_object(), "invalid upload reference");
    let allowed = [
        "schemaVersion",
        "sessionId",
        "ownerRuntimeId",
        "connectionId",
        "source",
        "target",
        "sourceVersion",
        "confirmedOffset",
        "expiresAt",
    ];
    ensure!(
        v.as_object()
            .unwrap()
            .keys()
            .all(|k| allowed.contains(&k.as_str())),
        "unknown upload reference field"
    );
    ensure!(
        v.get("schemaVersion").map_or(Some(1), Value::as_i64) == Some(1),
        "unsupported upload reference schema"
    );
    let id = v
        .get("sessionId")
        .and_then(Value::as_str)
        .context("upload session ID required")?;
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }),
        "invalid upload session ID"
    );
    for key in ["ownerRuntimeId", "connectionId", "sourceVersion"] {
        ensure!(
            v.get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty()),
            "incomplete upload reference"
        );
    }
    for key in ["confirmedOffset", "expiresAt"] {
        ensure!(
            v.get(key)
                .map_or(Some(0), Value::as_i64)
                .is_some_and(|n| n >= 0),
            "invalid upload progress"
        );
    }
    for key in ["source", "target"] {
        let endpoint = v
            .get(key)
            .and_then(Value::as_object)
            .context("upload endpoint required")?;
        ensure!(
            endpoint
                .keys()
                .all(|k| ["protocol", "protocolId", "path", "storageReference"]
                    .contains(&k.as_str())),
            "unknown endpoint field"
        );
        ensure!(
            endpoint
                .get("protocol")
                .map_or(Some("Local"), Value::as_str)
                .is_some_and(|s| ["Local", "Device", "Share", "Network"].contains(&s)),
            "invalid endpoint protocol"
        );
        for key in ["protocolId", "path"] {
            ensure!(
                endpoint.get(key).is_none_or(Value::is_string),
                "invalid upload endpoint"
            );
        }
        validate_reference(endpoint.get("storageReference").filter(|v| !v.is_null()))?;
    }
    Ok(())
}

pub(crate) fn probe<T>(result: Result<T>) -> Result<Availability> {
    match result {
        Ok(_) => Ok(Availability::Available),
        Err(error) => match error
            .downcast_ref::<crate::storage::http::HttpStatus>()
            .map(|s| s.0)
        {
            Some(401) => Ok(Availability::AuthorizationRequired),
            Some(403) => Ok(Availability::PermissionDenied),
            Some(404 | 405 | 501) => Ok(Availability::Unsupported),
            _ => Err(error),
        },
    }
}
pub(crate) struct ShareCompensation {
    store: Arc<Storage>,
    revoke: Option<std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>>,
}
impl ShareCompensation {
    pub fn new(
        store: Arc<Storage>,
        revoke: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) -> Self {
        Self {
            store,
            revoke: Some(Box::pin(revoke)),
        }
    }
    pub fn commit(mut self) {
        self.revoke = None;
    }
    pub async fn rollback(mut self) -> Result<()> {
        let done = self.cleanup().context(PlatformFailure)?;
        ensure!(
            done.await.unwrap_or(false),
            ResourceUnavailable("Share revocation could not be confirmed; refresh sharing state")
        );
        Ok(())
    }
    fn cleanup(&mut self) -> Option<tokio::sync::oneshot::Receiver<bool>> {
        let revoke = self.revoke.take()?;
        let (done, receiver) = tokio::sync::oneshot::channel();
        self.store.track_cleanup(tokio::spawn(async move {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), revoke).await;
            let _ = done.send(matches!(result, Ok(Ok(()))));
        }));
        Some(receiver)
    }
}
impl Drop for ShareCompensation {
    fn drop(&mut self) {
        self.cleanup();
    }
}
