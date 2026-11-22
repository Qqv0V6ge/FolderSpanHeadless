mod logical;
mod operations;
mod stages;
mod vault;
use super::{Client, Config, Entry, advanced::Path, validate_reference};
use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
    },
    storage::{
        accounts::{Storage, content::PasswordKeys},
        content_crypto::{ContentError, ErrorCode, canonical_uuid},
    },
};
use anyhow::{Context as _, Result, ensure};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

fn version() -> i32 {
    1
}
fn root_path() -> Path {
    Path {
        path: "/".into(),
        reference: None,
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Location {
    #[serde(default = "version")]
    format_version: i32,
    #[serde(default)]
    enabled: bool,
    #[serde(default = "root_path")]
    root: Path,
    #[serde(default)]
    vault_id: String,
}
fn location(config: &Config) -> Result<Option<Location>> {
    config
        .extras
        .get("contentEncryption")
        .filter(|v| !v.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}
fn cloud_text<'a>(config: &'a Config, name: &str) -> &'a str {
    config
        .extras
        .get("cloud")
        .and_then(|c| c.get(name))
        .and_then(Value::as_str)
        .unwrap_or("")
}
fn readonly(config: &Config) -> bool {
    config
        .extras
        .get("cloud")
        .and_then(|c| c.get("readOnly"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn scope(config: &Config) -> Result<String> {
    if let Some(reference) = location(config)? {
        ensure!(
            reference.root.path.starts_with('/')
                && !reference.root.path.chars().any(char::is_control),
            "invalid password location root"
        );
        crate::storage::remote::validate_write_path(&reference.root.path)?;
        if reference.vault_id.is_empty() {
            return Err(
                ContentError(ErrorCode::Locked, "password location requires verification").into(),
            );
        }
        ensure!(
            reference.format_version == 1,
            "unsupported password location reference"
        );
        canonical_uuid(&reference.vault_id)?;
        return Ok(serde_json::to_string(&[
            "password-location-v1",
            reference.vault_id.as_str(),
        ])?);
    }
    ensure!(
        !cloud_text(config, "connectionId").trim().is_empty(),
        "content encryption requires a stable connection identity"
    );
    Ok(serde_json::to_string(&[
        config.protocol.as_str(),
        cloud_text(config, "accountId"),
        cloud_text(config, "connectionId"),
        cloud_text(config, "rootId"),
        cloud_text(config, "libraryId"),
    ])?)
}
fn minimal_reference(reference: &Value) -> Result<Value> {
    validate_reference(Some(reference))?;
    let mut object = serde_json::Map::new();
    for key in ["id", "parentId", "ancestorId", "ancestorPath"] {
        if let Some(value) = reference
            .get(key)
            .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        {
            object.insert(key.into(), value.clone());
        }
    }
    if let Some(content) = reference.get("content").filter(|v| !v.is_null()) {
        let mut value = content.clone();
        for key in ["revisionId", "ordinaryPath"] {
            if value
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(str::is_empty)
            {
                value.as_object_mut().unwrap().remove(key);
            }
        }
        object.insert("content".into(), value);
    }
    Ok(Value::Object(object))
}
fn minimal_path(path: &Path) -> Result<String> {
    // Kotlin's default Json omits default reference fields in authorization ownership.
    let mut text = "{\"path\":".to_owned() + &serde_json::to_string(&path.path)?;
    if let Some(reference) = &path.reference {
        text.push_str(",\"reference\":");
        text.push_str(&serde_json::to_string(&minimal_reference(reference)?)?);
    }
    text.push('}');
    Ok(text)
}
fn authorization_owner(config: &Config, root: &Path) -> Result<String> {
    Ok(serde_json::to_string(&[
        "",
        config.protocol.as_str(),
        config.host.as_str(),
        config.username.as_str(),
        cloud_text(config, "accountId"),
        cloud_text(config, "connectionId"),
        cloud_text(config, "rootId"),
        cloud_text(config, "libraryId"),
        &minimal_path(root)?,
    ])?)
}
fn owner(store: &Storage, config: &Config, root: &Path) -> Result<String> {
    Ok(authorization_owner(config, root)?
        + "|"
        + &store.authorization_generation(&config.protocol, cloud_text(config, "accountId")))
}
fn provider_root(config: &Config) -> Path {
    let root = cloud_text(config, "rootId");
    let reference = match config.protocol.as_str() {
        "GoogleDrive" => Some(json!({"id":if root.trim().is_empty() {"root"} else {root}})),
        "Dropbox" => Some(json!({"id":if root.trim().is_empty() {"__root__"} else {root}})),
        _ => None,
    };
    Path {
        path: "/".into(),
        reference,
    }
}
fn new_uuid() -> Result<String> {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PlatformFailure)?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let text = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    ))
}
fn for_path(reference: &Value, old: &str, new: &str, directory: bool) -> Result<Option<Value>> {
    validate_reference(Some(reference))?;
    if old == new {
        return Ok(Some(reference.clone()));
    }
    let text = |key: &str| reference.get(key).and_then(Value::as_str).unwrap_or("");
    if let Some(content) = reference.get("content").filter(|v| !v.is_null()) {
        if directory && new.starts_with(&(old.trim_end_matches('/').to_owned() + "/")) {
            let relative = &new[old.trim_end_matches('/').len() + 1..];
            let mut content = content.clone();
            let suffix = [
                content
                    .get("ordinaryPath")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim_matches('/'),
                relative,
            ]
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join("/");
            content["revisionId"] = json!("");
            content["ordinaryPath"] = json!(suffix);
            return Ok(Some(json!({"content":content})));
        }
        return Ok(None);
    }
    let prefix = old.trim_end_matches('/').to_owned() + "/";
    if directory && !text("id").is_empty() && new.starts_with(&prefix) {
        return Ok(Some(json!({"ancestorId":text("id"),"ancestorPath":old})));
    }
    let parent = old
        .rsplit_once('/')
        .map(|(p, _)| p)
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    let new_parent = new
        .rsplit_once('/')
        .map(|(p, _)| p)
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    if !text("parentId").is_empty() {
        if new == parent {
            return Ok(Some(json!({"id":text("parentId")})));
        }
        if new_parent == parent {
            return Ok(Some(
                json!({"ancestorId":text("parentId"),"ancestorPath":parent}),
            ));
        }
    }
    if !text("ancestorId").is_empty() {
        if new == text("ancestorPath") {
            return Ok(Some(json!({"id":text("ancestorId")})));
        }
        if new.starts_with(&(text("ancestorPath").trim_end_matches('/').to_owned() + "/")) {
            let mut reference = reference.clone();
            reference["id"] = json!("");
            reference["parentId"] = json!("");
            return Ok(Some(reference));
        }
    }
    Ok(None)
}
fn child_path(parent: &Path, name: &str) -> Result<Path> {
    let path = parent.path.trim_end_matches('/').to_owned() + "/" + name;
    Ok(Path {
        reference: parent
            .reference
            .as_ref()
            .map(|r| for_path(r, &parent.path, &path, true))
            .transpose()?
            .flatten(),
        path,
    })
}
pub(crate) struct Host {
    pub cache_root: PathBuf,
    pub files: Arc<crate::storage::files::FilePolicy>,
}
struct Content {
    work: Arc<Mutex<()>>,
    files: Arc<crate::storage::files::FilePolicy>,
    keys: PasswordKeys,
    closed: bool,
    stages: stages::Stages,
}
struct Handle {
    state: Arc<Mutex<Content>>,
    cancel: CancellationToken,
}
fn open(session: &Arc<Session>, store: &Arc<Storage>, host: Host) -> Result<Reply> {
    let state = Arc::new(Mutex::new(Content {
        work: Arc::new(Mutex::new(())),
        keys: PasswordKeys::new(store.clone()),
        files: host.files,
        closed: false,
        stages: stages::Stages::new(host.cache_root)?,
    }));
    let cancel = CancellationToken::new();
    let (close, closed) = oneshot::channel::<()>();
    let value = state.clone();
    let close_cancel = cancel.clone();
    let cleanup = tokio::spawn(async move {
        let _ = closed.await;
        let mut state = value.lock_owned().await;
        let _work = state.work.clone().lock_owned().await;
        close_cancel.cancel();
        let _ = tokio::task::spawn_blocking(move || {
            state.closed = true;
            state.keys.close();
            state.stages.close();
        })
        .await;
    });
    let id = session.own_with_cleanup(
        Handle { state, cancel },
        move || {
            let _ = close.send(());
        },
        cleanup,
    )?;
    Ok(Reply::json(json!({"id":id})))
}

#[derive(Default, Clone, Copy, Deserialize, Serialize)]
enum Protocol {
    #[default]
    Local,
    Device,
    Share,
    Network,
}
#[derive(Default, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Sensitivity {
    #[default]
    None,
    Sensitive,
    Critical,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileInfo {
    name: String,
    #[serde(default)]
    description: String,
    is_directory: bool,
    is_hidden: bool,
    path: String,
    mine_type: String,
    size: i64,
    created_date: i64,
    updated_date: i64,
    #[serde(default)]
    protocol: Protocol,
    #[serde(default)]
    protocol_id: String,
    #[serde(default)]
    is_ignored: bool,
    #[serde(default)]
    is_symbolic_link: bool,
    #[serde(default)]
    is_symbolic_link_known: bool,
    #[serde(default)]
    sensitivity: Sensitivity,
    #[serde(default)]
    sensitivity_category: String,
    #[serde(
        default,
        deserialize_with = "crate::storage::remote::deserialize_reference",
        serialize_with = "crate::storage::remote::serialize_reference"
    )]
    storage_reference: Option<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    handle: String,
    #[serde(default)]
    config: Option<Config>,
    #[serde(default)]
    task_key: i64,
    #[serde(default)]
    entry_id: String,
    #[serde(default)]
    file: Option<FileInfo>,
    #[serde(default)]
    staged_path: String,
    #[serde(default)]
    destination_path: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    entry: Option<Entry>,
    #[serde(default)]
    task_reference: String,
    #[serde(default)]
    target: Option<Path>,
    #[serde(default)]
    destination: Option<Path>,
    #[serde(default)]
    is_directory: bool,
    #[serde(default)]
    expected_identity: String,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub(crate) async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
    store: &Arc<Storage>,
    host: Host,
    password_allowed: bool,
) -> Result<Reply> {
    let body = Zeroizing::new(body);
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let op = path
        .strip_prefix("/api/web-ui/platform/storage/content/")
        .context("invalid content route")?;
    if op == "private-file" {
        ensure!(
            matches!(method, "GET" | "PUT" | "DELETE"),
            "unsupported private file method"
        );
        let query = crate::management::wire::query(query);
        let handle = query.get("handle").context("content handle required")?;
        let resource = session
            .resource_value(handle)?
            .downcast::<Handle>()
            .map_err(|_| ResourceUnavailable("not a content handle"))?;
        let mut state = resource.state.clone().lock_owned().await;
        // A cancelled async request can leave a blocking file operation finishing.
        drop(state.work.clone().lock_owned().await);
        ensure!(!state.closed, ResourceUnavailable("content context closed"));
        let method = method.to_owned();
        return tokio::task::spawn_blocking(move || {
            state.stages.private_file(&method, &query, &body)
        })
        .await
        .map_err(|_| PlatformFailure)?;
    }
    ensure!(method == "POST", "unsupported content method");
    if op == "open" {
        return open(session, store, host);
    }
    if ["create", "export", "verify", "import", "unlock"].contains(&op) {
        return Err(ContentError(
            ErrorCode::Unavailable,
            "use the location content password; recovery files are not supported",
        )
        .into());
    }
    if matches!(op, "setup-password" | "unlock-password") {
        ensure!(
            crate::management::wire::query(query).is_empty(),
            "content passwords must use the request body"
        );
        ensure!(
            password_allowed,
            "content passwords require HTTPS or a local Runtime"
        );
    }
    let input: Request = serde_json::from_slice(&body)?;
    ensure!(
        input.password.is_empty() || matches!(op, "setup-password" | "unlock-password"),
        "content password not valid for this operation"
    );
    ensure!(
        input.password.encode_utf16().count() <= 1024,
        "content password too long"
    );
    let resource = session
        .resource_value(&input.handle)?
        .downcast::<Handle>()
        .map_err(|_| ResourceUnavailable("not a content handle"))?;
    let cancel = resource.cancel.child_token();
    let _cancel_on_drop = cancel.clone().drop_guard();
    let mut state = resource.state.clone().lock_owned().await;
    // A cancelled async request can leave a blocking file operation finishing.
    drop(state.work.clone().lock_owned().await);
    ensure!(
        !state.closed && !resource.cancel.is_cancelled(),
        ResourceUnavailable("content context closed")
    );
    if matches!(
        op,
        "stage" | "stage-identity" | "stage-complete" | "cleanup"
    ) {
        let store = store.clone();
        let op = op.to_owned();
        return tokio::task::spawn_blocking(move || {
            let task = state.stages.task(&store, &input, op == "stage")?;
            match op.as_str() {
                "stage" => Ok(Reply::json(state.stages.create(task)?)),
                "stage-identity" => Ok(Reply::json(
                    state.stages.identity(task, &input.staged_path)?,
                )),
                "stage-complete" => {
                    ensure!(
                        state.stages.is_plain(task, &input.staged_path),
                        "encrypted upload sources are read-only"
                    );
                    state
                        .stages
                        .complete(task, &input.staged_path, &input.expected_identity)?;
                    Ok(Reply::json(true))
                }
                "cleanup" => {
                    state.stages.cleanup(&store, &input)?;
                    Ok(Reply::json(true))
                }
                _ => unreachable!(),
            }
        })
        .await
        .map_err(|_| PlatformFailure)?;
    }
    let config = input.config.as_ref().context("content config required")?;
    let reference = location(config)?;
    if op == "inspect" && reference.as_ref().is_some_and(|r| r.format_version != 1) {
        return Err(ContentError(
            ErrorCode::UnsupportedFormat,
            "unsupported password location reference",
        )
        .into());
    }
    if op == "status" && reference.is_none() && cloud_text(config, "connectionId").trim().is_empty()
    {
        return Ok(Reply::json(
            json!({"scope":"","enabled":false,"unlocked":false,"backupVerified":false,
            "available":false,"hasKey":false,"metadataProtectionAvailable":false}),
        ));
    }
    if op == "lock" {
        let scope = scope(config)?;
        if let Some(reference) = &reference {
            state
                .keys
                .lock(&scope, &authorization_owner(config, &reference.root)?);
        }
        return Ok(Reply::json(true));
    }
    if op == "enabled" && !input.enabled && reference.is_some() {
        return Ok(Reply::json(true));
    }
    if !matches!(
        op,
        "inspect" | "setup-password" | "unlock-password" | "status" | "enabled"
    ) {
        return operations::Operation {
            config,
            store,
            session,
            cancel: &cancel,
        }
        .handle(op, &input, &mut state)
        .await;
    }
    let client = Client::create(config, Some(store), session, "")?;
    let permissions = client.capabilities();
    let read = permissions["read"] == true;
    let write = permissions["write"] == true;
    match op {
        "inspect" => {
            let root = reference
                .as_ref()
                .filter(|r| !r.vault_id.is_empty())
                .map(|r| r.root.clone())
                .unwrap_or_else(|| provider_root(config));
            ensure!(
                root.path.starts_with('/') && !root.path.chars().any(char::is_control),
                "invalid password root"
            );
            crate::storage::remote::validate_write_path(&root.path)?;
            let known = reference
                .as_ref()
                .map(|r| r.vault_id.as_str())
                .unwrap_or("");
            let id = if read {
                vault::Vault::new(
                    &client,
                    &root,
                    store,
                    &owner(store, config, &root)?,
                    &cancel,
                )?
                .inspect(known)
                .await?
            } else {
                None
            };
            let reference = id.map(|id| Location {
                format_version: 1,
                enabled: false,
                root: root.clone(),
                vault_id: id,
            });
            Ok(Reply::json(
                json!({"available":read,"writable":read&&write&&!readonly(config),"root":root,"reference":reference}),
            ))
        }
        "setup-password" => {
            if !write || readonly(config) {
                return Err(ContentError(ErrorCode::ReadOnly, "this location is read-only").into());
            }
            if let Some(r) = &reference {
                ensure!(
                    r.format_version == 1,
                    "unsupported password location reference"
                );
                if !r.vault_id.is_empty() {
                    scope(config)?;
                }
            }
            let root = reference
                .as_ref()
                .map(|r| r.root.clone())
                .unwrap_or_else(|| provider_root(config));
            let before = owner(store, config, &root)?;
            let vault = vault::Vault::new(&client, &root, store, &before, &cancel)?;
            let (id, key) = vault
                .initialize_or_unlock(
                    &input.password,
                    reference
                        .as_ref()
                        .map(|r| r.vault_id.as_str())
                        .unwrap_or(""),
                )
                .await?;
            ensure!(
                before == owner(store, config, &root)?,
                ResourceUnavailable("authorization changed while setting content password")
            );
            let scope = serde_json::to_string(&["password-location-v1", id.as_str()])?;
            state
                .keys
                .unlock(&scope, &before, &authorization_owner(config, &root)?, &key)?;
            Ok(Reply::json(Location {
                format_version: 1,
                enabled: true,
                root,
                vault_id: id,
            }))
        }
        "unlock-password" => {
            let reference = reference
                .as_ref()
                .context("password location reference missing")?;
            let scope = scope(config)?;
            let before = owner(store, config, &reference.root)?;
            let vault = vault::Vault::new(&client, &reference.root, store, &before, &cancel)?;
            let (_, key) = vault.unlock(&input.password, &reference.vault_id).await?;
            ensure!(
                before == owner(store, config, &reference.root)?,
                ResourceUnavailable("authorization changed while unlocking content")
            );
            state.keys.unlock(
                &scope,
                &before,
                &authorization_owner(config, &reference.root)?,
                &key,
            )?;
            Ok(Reply::json(true))
        }
        "status" => {
            let scope = scope(config)?;
            let (has_key, unlocked) = if let Some(r) = &reference {
                state.keys.status(&scope, &owner(store, config, &r.root)?)?
            } else {
                (false, false)
            };
            Ok(Reply::json(
                json!({"scope":scope,"enabled":reference.as_ref().is_some_and(|r|r.enabled),
                "unlocked":unlocked,"backupVerified":false,"available":if reference.is_some(){read}else{true},"hasKey":has_key,
                 "metadataProtectionAvailable":if reference.is_some(){write}else{config.protocol=="Dropbox"}}),
            ))
        }
        "enabled" => {
            let reference = reference
                .as_ref()
                .context(ResourceUnavailable("content key unavailable"))?;
            let scope = scope(config)?;
            if input.enabled {
                if !write || readonly(config) {
                    return Err(
                        ContentError(ErrorCode::ReadOnly, "this location is read-only").into(),
                    );
                }
                let owner = owner(store, config, &reference.root)?;
                let key = state.keys.key(&scope, &owner)?;
                vault::Vault::new(&client, &reference.root, store, &owner, &cancel)?
                    .history(&reference.vault_id, &key, true)
                    .await?;
            }
            Ok(Reply::json(true))
        }
        _ => Err(ResourceUnavailable("unknown content operation").into()),
    }
}

#[cfg(test)]
mod tests;
