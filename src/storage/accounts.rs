mod cipher;
pub mod content;
#[cfg(feature = "pro")]
#[rustfmt::skip]
#[path = "../../pro/src/storage/accounts/oauth.rs"]
mod oauth;
mod uploads;
use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
    },
    runtime::config::{private_directory, random_id, write_private},
    storage::remote::http_directory::client,
};
use anyhow::{Context, Result, ensure};
use cipher::{AccountCipher, MAGIC, OVERHEAD};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const STATE_LIMIT: usize = 32 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Kind {
    GoogleDrive,
    Dropbox,
    Nextcloud,
    Seafile,
}
impl Kind {
    fn protocol(value: &str) -> Result<Self> {
        match value {
            "GoogleDrive" => Ok(Self::GoogleDrive),
            "Dropbox" => Ok(Self::Dropbox),
            "Nextcloud" => Ok(Self::Nextcloud),
            "Seafile" => Ok(Self::Seafile),
            _ => Err(ResourceUnavailable("This storage provider does not use an account").into()),
        }
    }
    fn available(self, broker: Option<&str>) -> Result<()> {
        ensure!(
            !matches!(self, Self::GoogleDrive | Self::Dropbox) || broker.is_some(),
            ResourceUnavailable(
                "Official storage authorization is available only in the Pro edition"
            )
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Credential {
    pub id: String,
    pub kind: Kind,
    pub provider_account_id: String,
    pub label: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub server: String,
    pub access_token: String,
    #[serde(default = "unlimited_expiry")]
    pub expires_at: i64,
    #[serde(default)]
    pub broker_url: String,
    #[serde(default)]
    pub broker_grant: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub library_id: String,
    #[serde(default)]
    pub requires_authorization: bool,
}
fn unlimited_expiry() -> i64 {
    i64::MAX
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.broker_grant.zeroize();
    }
}
impl Credential {
    fn metadata(&self) -> Value {
        json!({"id":self.id,"kind":self.kind,"label":self.label,"username":self.username,"server":self.server,
            "needsAuthorization":self.requires_authorization || self.access_token.is_empty() && self.broker_grant.is_empty(),
            "readOnly":self.read_only,"libraryId":self.library_id})
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    #[serde(default)]
    upload_owner: String,
    #[serde(default)]
    content: BTreeMap<String, Zeroizing<String>>,
    #[serde(default)]
    uploads: BTreeMap<String, uploads::Record>,
    accounts: BTreeMap<String, Credential>,
    generations: BTreeMap<String, String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            upload_owner: String::new(),
            content: BTreeMap::new(),
            uploads: BTreeMap::new(),
            accounts: BTreeMap::new(),
            generations: BTreeMap::new(),
        }
    }
}
pub struct Storage {
    path: PathBuf,
    cipher: AccountCipher,
    state: Mutex<State>,
    client: Client,
    pending: Arc<Semaphore>,
    broker: Option<String>,
    #[cfg(feature = "pro")]
    refresh_locks: Mutex<BTreeMap<String, std::sync::Weak<AsyncMutex<()>>>>,
    cleanup: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
pub(crate) fn canonical_server(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control) && !value.contains('\\'),
        "invalid storage server"
    );
    let url = Url::parse(value)?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none_or(str::is_empty)
            && url.query().is_none_or(str::is_empty)
            && url.fragment().is_none_or(str::is_empty),
        "invalid storage server"
    );
    let mut url = url;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
fn scoped_login_url(server: &str, value: &str) -> Result<String> {
    let base = Url::parse(server)?;
    let target = Url::parse(value)?;
    let prefix = base.path().trim_end_matches('/');
    ensure!(
        base.origin() == target.origin()
            && target.username().is_empty()
            && target.password().is_none_or(str::is_empty)
            && (prefix.is_empty() || target.path().starts_with(&format!("{prefix}/"))),
        "Nextcloud authorization URL leaves the configured instance"
    );
    Ok(target.into())
}
fn account_id(value: &str) -> Result<()> {
    ensure!(
        (16..=64).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid storage account reference"
    );
    Ok(())
}
pub(crate) fn string(value: &Value, key: &str) -> Result<String> {
    match value.get(key) {
        Some(Value::String(v)) => Ok(v.clone()),
        Some(Value::Bool(v)) => Ok(v.to_string()),
        Some(Value::Number(v)) => Ok(v.to_string()),
        _ => Err(ResourceUnavailable("invalid storage metadata").into()),
    }
}
fn take_string(value: &mut Value, key: &str) -> Result<String> {
    let member = value
        .get_mut(key)
        .context(ResourceUnavailable("invalid storage metadata"))?
        .take();
    match member {
        Value::String(v) => Ok(v),
        Value::Number(v) => Ok(v.to_string()),
        Value::Bool(v) => Ok(v.to_string()),
        _ => Err(ResourceUnavailable("invalid storage metadata").into()),
    }
}
fn optional_string(value: &Value, key: &str) -> Option<String> {
    string(value, key).ok()
}
pub(crate) async fn read_json(response: Response, limit: usize) -> Result<Value> {
    let data = crate::storage::http::body(response, limit).await?;
    serde_json::from_slice(&data)
        .map_err(|_| ResourceUnavailable("invalid storage response").into())
}
fn success(response: Response) -> Result<Response> {
    ensure!(response.status().is_success(), PlatformFailure);
    Ok(response)
}
impl Storage {
    pub fn load(directory: &Path) -> Result<Arc<Self>> {
        private_directory(directory)?;
        let path = directory.join("storage-accounts.json");
        let existing = match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.len() <= (STATE_LIMIT + OVERHEAD) as u64,
                    "invalid private storage account file"
                );
                let bytes = Zeroizing::new(std::fs::read(&path)?);
                ensure!(
                    bytes.len() <= STATE_LIMIT + OVERHEAD,
                    "storage account file exceeds limit"
                );
                Some(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let encrypted = existing.as_ref().is_some_and(|b| b.starts_with(MAGIC));
        let parse = |bytes: &[u8]| -> Result<State> {
            ensure!(
                bytes.len() <= STATE_LIMIT,
                "storage account state exceeds limit"
            );
            let state: State = serde_json::from_slice(bytes)
                .map_err(|_| anyhow::anyhow!("stored storage accounts require authorization"))?;
            ensure!(state.version == 1, "unsupported storage account state");
            for (id, value) in &state.accounts {
                account_id(id)?;
                ensure!(*id == value.id, "invalid stored storage account");
            }
            Ok(state)
        };
        // Only this project's valid plaintext preview format is upgraded; JVM settings are never read.
        let plaintext = if !encrypted {
            existing.as_ref().map(|b| parse(b)).transpose()?
        } else {
            None
        };
        let cipher = AccountCipher::load(directory, !encrypted)?;
        let state = if encrypted {
            parse(&cipher.open(existing.as_ref().unwrap())?)?
        } else {
            plaintext.unwrap_or_default()
        };
        let store = Arc::new(Self {
            path,
            cipher,
            state: Mutex::new(state),
            client: client()?,
            pending: Arc::new(Semaphore::new(32)),
            #[cfg(feature = "pro")]
            broker: oauth::installed_broker()?,
            #[cfg(not(feature = "pro"))]
            broker: None,
            #[cfg(feature = "pro")]
            refresh_locks: Mutex::new(BTreeMap::new()),
            cleanup: Mutex::new(Vec::new()),
        });
        if existing.is_some() && !encrypted {
            store.save(&store.state.lock().unwrap())?;
        }
        Ok(store)
    }
    pub(crate) fn upload_owner(&self) -> Result<String> {
        let mut state = self.state.lock().unwrap();
        if state.upload_owner.is_empty() {
            let mut next = state.clone();
            let id = hex::encode(rand::random::<[u8; 16]>());
            next.upload_owner = format!(
                "{}-{}-{}-{}-{}",
                &id[..8],
                &id[8..12],
                &id[12..16],
                &id[16..20],
                &id[20..]
            );
            self.save(&next)?;
            *state = next;
        }
        Ok(state.upload_owner.clone())
    }
    pub(crate) fn track_cleanup(&self, task: tokio::task::JoinHandle<()>) {
        let mut tasks = self.cleanup.lock().unwrap();
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
    }
    pub async fn finish_cleanup(&self) {
        loop {
            let tasks = std::mem::take(&mut *self.cleanup.lock().unwrap());
            if tasks.is_empty() {
                return;
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    }
    fn save(&self, state: &State) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(state)?);
        ensure!(
            bytes.len() <= STATE_LIMIT,
            ResourceUnavailable("storage account state exceeds limit")
        );
        let encrypted = self.cipher.seal(bytes)?;
        write_private(&self.path, &encrypted).map_err(|_| PlatformFailure)?;
        Ok(())
    }
    pub fn accounts(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .values()
            .map(Credential::metadata)
            .collect()
    }
    pub(crate) fn metadata(&self, id: &str) -> Result<Credential> {
        account_id(id)?;
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(id)
            .cloned()
            .ok_or_else(|| ResourceUnavailable("Storage account requires authorization").into())
    }
    fn install(&self, mut value: Credential, replace: Option<&str>) -> Result<Value> {
        ensure!(
            (1..=4096).contains(&value.provider_account_id.encode_utf16().count())
                && value.label.encode_utf16().count() <= 4096
                && (1..=64 * 1024).contains(&value.access_token.encode_utf16().count()),
            "invalid storage account credentials"
        );
        let mut state = self.state.lock().unwrap();
        if let Some(id) = replace {
            account_id(id)?;
            let old = state.accounts.get(id).context(ResourceUnavailable(
                "Storage account requires authorization",
            ))?;
            ensure!(
                old.kind == value.kind
                    && old.provider_account_id == value.provider_account_id
                    && old.server == value.server,
                ResourceUnavailable(
                    "Reauthorize with the original storage account, or create a new connection"
                )
            );
            value.id = id.into();
        }
        account_id(&value.id)?;
        let result = value.metadata();
        let mut next = state.clone();
        next.generations.insert(value.id.clone(), random_id(16));
        next.accounts.insert(value.id.clone(), value);
        self.save(&next)?;
        *state = next;
        Ok(result)
    }
    pub(crate) fn credential(
        &self,
        protocol: &str,
        host: &str,
        account: &str,
        library: &str,
    ) -> Result<Credential> {
        let kind = Kind::protocol(protocol)?;
        kind.available(self.broker.as_deref())?;
        let value = self.metadata(account)?;
        ensure!(
            value.kind == kind,
            ResourceUnavailable("Storage account belongs to another provider")
        );
        ensure!(
            !matches!(kind, Kind::Nextcloud | Kind::Seafile)
                || canonical_server(host)? == value.server,
            ResourceUnavailable("Storage account belongs to another server")
        );
        ensure!(
            value.library_id.is_empty() || value.library_id == library,
            ResourceUnavailable("Storage token belongs to another library")
        );
        ensure!(
            !value.requires_authorization
                && (!value.access_token.is_empty() || !value.broker_grant.is_empty()),
            ResourceUnavailable("Storage account requires authorization")
        );
        Ok(value)
    }
    async fn revoke(&self, value: &Credential) -> Result<()> {
        if value.kind != Kind::Nextcloud {
            #[cfg(feature = "pro")]
            self.revoke_broker_grant(value).await?;
            return Ok(());
        }
        let response = self
            .client
            .delete(format!(
                "{}/ocs/v2.php/core/apppassword?format=json",
                value.server
            ))
            .basic_auth(&value.username, Some(&value.access_token))
            .header("OCS-APIRequest", "true")
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(
            response.status().is_success(),
            ResourceUnavailable("Local credentials removed; Nextcloud revocation failed")
        );
        Ok(())
    }
    async fn revoke_uninstalled(&self, value: &Credential) -> Result<()> {
        #[cfg(feature = "pro")]
        if value.kind != Kind::Nextcloud {
            return self.revoke_uninstalled_broker_grant(value).await;
        }
        self.revoke(value).await
    }

    async fn remove(&self, id: &str) -> Result<()> {
        account_id(id)?;
        let value = {
            let mut state = self.state.lock().unwrap();
            let value = state
                .accounts
                .get(id)
                .cloned()
                .context(ResourceUnavailable(
                    "Storage account requires authorization",
                ))?;
            let mut next = state.clone();
            next.accounts.remove(id);
            next.generations.insert(id.into(), random_id(16));
            self.save(&next)?;
            *state = next;
            value
        };
        self.revoke(&value).await?;
        Ok(())
    }
    async fn bearer_json(&self, value: &Credential, suffix: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}{suffix}", value.server))
            .bearer_auth(&value.access_token)
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        read_json(success(response)?, 8 * RESPONSE_LIMIT).await
    }
    async fn seafile(&self, request: SeafileRequest) -> Result<Value> {
        let server = canonical_server(&request.server)?;
        ensure!(
            !request.token.trim().is_empty()
                && request.token.encode_utf16().count() <= 4096
                && !request.token.chars().any(char::is_control),
            "invalid Seafile token"
        );
        let mut value = Credential {
            id: random_id(16),
            kind: Kind::Seafile,
            provider_account_id: String::new(),
            label: String::new(),
            server,
            username: String::new(),
            access_token: request.token.clone(),
            expires_at: i64::MAX,
            broker_url: String::new(),
            broker_grant: String::new(),
            read_only: false,
            library_id: String::new(),
            requires_authorization: false,
        };
        let identity = self
            .bearer_json(
                &value,
                if request.repo_token {
                    "/api/v2.1/via-repo-token/repo-info/"
                } else {
                    "/api2/account/info/"
                },
            )
            .await?;
        if request.repo_token {
            value.library_id = string(&identity, "repo_id")?;
            ensure!(
                request.library_id.is_empty() || request.library_id == value.library_id,
                "Seafile token belongs to another library"
            );
            value.provider_account_id = format!("repo:{}", value.library_id);
            value.label =
                optional_string(&identity, "repo_name").unwrap_or_else(|| "Seafile".into());
            let directory = self
                .bearer_json(&value, "/api/v2.1/via-repo-token/dir/?path=%2F")
                .await?;
            value.read_only = optional_string(&directory, "user_perm").as_deref() != Some("rw");
        } else {
            value.provider_account_id = string(&identity, "email")?;
            value.label = optional_string(&identity, "email").unwrap_or_else(|| "Seafile".into());
        }
        self.install(value, request.replace_account_id.as_deref())
    }
    async fn libraries(&self, id: &str) -> Result<Value> {
        let meta = self.metadata(id)?;
        ensure!(meta.kind == Kind::Seafile, "not a Seafile account");
        let value = self.credential("Seafile", &meta.server, id, &meta.library_id)?;
        if !value.library_id.is_empty() {
            let result = self
                .bearer_json(&value, "/api/v2.1/via-repo-token/repo-info/")
                .await?;
            ensure!(
                string(&result, "repo_id")? == value.library_id,
                ResourceUnavailable("Seafile token belongs to another library")
            );
            return Ok(
                json!([{"id":value.library_id,"name":string(&result,"repo_name")?,"readOnly":value.read_only}]),
            );
        }
        let result = self.bearer_json(&value, "/api2/repos/").await?;
        let list = result
            .as_array()
            .context(ResourceUnavailable("invalid Seafile library list"))?;
        ensure!(
            list.len() <= 500_000,
            ResourceUnavailable("Seafile library limit")
        );
        Ok(Value::Array(
            list.iter()
                .map(|item| {
                    Ok(json!({"id":string(item,"id")?,"name":string(item,"name")?,
            "readOnly":optional_string(item,"permission").as_deref()!=Some("rw")}))
                })
                .collect::<Result<_>>()?,
        ))
    }
    async fn begin(
        self: &Arc<Self>,
        request: AuthorizationRequest,
        session: &Arc<Session>,
    ) -> Result<Value> {
        let kind = Kind::protocol(&request.protocol)?;
        ensure!(
            request.permissions.is_empty()
                || matches!(kind, Kind::GoogleDrive | Kind::Dropbox)
                    && request
                        .replace_account_id
                        .as_ref()
                        .is_some_and(|s| !s.trim().is_empty()),
            "Additional storage permissions require reauthorization of an existing OAuth account"
        );
        ensure!(kind != Kind::Seafile, "Seafile uses token authorization");
        if let Some(id) = &request.replace_account_id {
            ensure!(
                self.metadata(id)?.kind == kind,
                ResourceUnavailable("Storage account belongs to another provider")
            );
        }
        kind.available(self.broker.as_deref())?;
        #[cfg(feature = "pro")]
        if matches!(kind, Kind::GoogleDrive | Kind::Dropbox) {
            return oauth::begin(self, request, session).await;
        }
        let slot = self.pending.clone().try_acquire_owned().map_err(|_| {
            ResourceUnavailable("Too many storage authorizations; cancel an existing one")
        })?;
        let server = canonical_server(&request.server)?;
        let response = self
            .client
            .post(format!("{server}/index.php/login/v2"))
            .header("User-Agent", "FolderSpan")
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        let mut result = read_json(success(response)?, RESPONSE_LIMIT).await?;
        let login = scoped_login_url(&server, &string(&result, "login")?)?;
        let poll = result
            .get_mut("poll")
            .context(ResourceUnavailable("invalid Nextcloud poll metadata"))?;
        let endpoint = scoped_login_url(&server, &string(poll, "endpoint")?)?;
        let token = take_string(poll, "token")?;
        let expires = now() + 20 * 60_000;
        let cancel = CancellationToken::new();
        let close = cancel.clone();
        let slot = Arc::new(Mutex::new(Some(slot)));
        let slot_close = slot.clone();
        let resource = Authorization {
            state: AsyncMutex::new(Some(Pending {
                server,
                endpoint,
                token,
                expires,
                replace: request.replace_account_id,
            })),
            cancel,
            slot,
        };
        let handle = session.own_with_close(resource, move || {
            close.cancel();
            slot_close.lock().unwrap().take();
        })?;
        Ok(
            json!({"handle":handle,"loginUrl":login,"userCode":"","expiresAt":expires,"acceptedPermissions":[]}),
        )
    }
    async fn poll(self: &Arc<Self>, resource: &Authorization) -> Result<Value> {
        tokio::select! {
            biased;
            _=resource.cancel.cancelled()=>Err(ResourceUnavailable("Storage authorization cancelled").into()),
            result=self.poll_active(resource)=>result,
        }
    }
    async fn poll_active(self: &Arc<Self>, resource: &Authorization) -> Result<Value> {
        let mut state = resource.state.lock().await;
        let pending = state.as_ref().context(ResourceUnavailable(
            "Storage authorization expired or cancelled",
        ))?;
        if now() >= pending.expires {
            *state = None;
            resource.slot.lock().unwrap().take();
            return Ok(json!({"status":"expired","account":null}));
        }
        let response = self
            .client
            .post(&pending.endpoint)
            .form(&[("token", &pending.token)])
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(json!({"status":"pending","account":null}));
        }
        let mut result = read_json(success(response)?, RESPONSE_LIMIT).await?;
        ensure!(
            canonical_server(&string(&result, "server")?)? == pending.server,
            ResourceUnavailable("Nextcloud returned another server")
        );
        let username = string(&result, "loginName")?;
        let password = Zeroizing::new(take_string(&mut result, "appPassword")?);
        ensure!(
            !username.is_empty() && !password.is_empty(),
            "invalid Nextcloud app password"
        );
        let value = Credential {
            id: random_id(16),
            kind: Kind::Nextcloud,
            provider_account_id: String::new(),
            label: String::new(),
            username,
            server: pending.server.clone(),
            access_token: password.to_string(),
            expires_at: i64::MAX,
            broker_url: String::new(),
            broker_grant: String::new(),
            read_only: false,
            library_id: String::new(),
            requires_authorization: false,
        };
        let mut grant = Uninstalled {
            store: self.clone(),
            value: Some(value),
        };
        let operation = async {
            let value = grant.value.as_mut().unwrap();
            let response = self
                .client
                .get(format!(
                    "{}/ocs/v2.php/cloud/user?format=json",
                    value.server
                ))
                .basic_auth(&value.username, Some(&value.access_token))
                .header("OCS-APIRequest", "true")
                .send()
                .await
                .map_err(|_| PlatformFailure)?;
            let user = read_json(success(response)?, RESPONSE_LIMIT).await?;
            let user = user
                .get("ocs")
                .and_then(|v| v.get("data"))
                .context(ResourceUnavailable("invalid Nextcloud identity"))?;
            value.provider_account_id = string(user, "id")?;
            value.label =
                optional_string(user, "display-name").unwrap_or_else(|| value.username.clone());
            ensure!(
                !resource.cancel.is_cancelled(),
                ResourceUnavailable("Storage authorization cancelled")
            );
            self.install(value.clone(), pending.replace.as_deref())
        }
        .await;
        match operation {
            Ok(account) => {
                grant.value.take();
                *state = None;
                resource.slot.lock().unwrap().take();
                Ok(json!({"status":"authorized","account":account}))
            }
            Err(error) => {
                if let Some(task) = grant.cleanup() {
                    let _ = task.await;
                }
                *state = None;
                resource.slot.lock().unwrap().take();
                Err(error)
            }
        }
    }
}
struct Uninstalled {
    store: Arc<Storage>,
    value: Option<Credential>,
}
impl Uninstalled {
    fn cleanup(&mut self) -> Option<tokio::sync::oneshot::Receiver<()>> {
        let value = self.value.take()?;
        let store = self.store.clone();
        let (done, receiver) = tokio::sync::oneshot::channel();
        let mut tasks = self.store.cleanup.lock().unwrap();
        tasks.retain(|t| !t.is_finished());
        tasks.push(tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(3), store.revoke_uninstalled(&value))
                .await;
            let _ = done.send(());
        }));
        Some(receiver)
    }
}
impl Drop for Uninstalled {
    fn drop(&mut self) {
        self.cleanup();
    }
}

struct Pending {
    server: String,
    endpoint: String,
    token: String,
    expires: i64,
    replace: Option<String>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
struct Authorization {
    state: AsyncMutex<Option<Pending>>,
    cancel: CancellationToken,
    slot: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
}
#[derive(Deserialize)]
enum Permission {
    #[serde(rename = "SHARING")]
    Sharing,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationRequest {
    protocol: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    replace_account_id: Option<String>,
    #[serde(default)]
    permissions: Vec<Permission>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeafileRequest {
    server: String,
    token: String,
    #[serde(default)]
    repo_token: bool,
    #[serde(default)]
    library_id: String,
    #[serde(default)]
    replace_account_id: Option<String>,
}
impl Drop for SeafileRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
#[derive(Deserialize)]
struct Handle {
    handle: String,
}
#[derive(Deserialize)]
struct Account {
    id: String,
}

pub async fn handle(
    method: &str,
    path: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
    store: &Arc<Storage>,
) -> Result<Reply> {
    let body = Zeroizing::new(body);
    let operation = path
        .split('?')
        .next()
        .unwrap_or(path)
        .strip_prefix("/api/web-ui/platform/storage")
        .context("invalid storage route")?;
    Ok(match (method, operation) {
        ("GET", "/accounts") => Reply::json(store.accounts()),
        ("POST", "/start") => Reply::json(
            store
                .begin(
                    serde_json::from_slice(&body).map_err(|_| {
                        ResourceUnavailable("Invalid storage authorization request")
                    })?,
                    session,
                )
                .await?,
        ),
        ("POST", "/seafile") => {
            Reply::json(
                store
                    .seafile(serde_json::from_slice(&body).map_err(|_| {
                        ResourceUnavailable("Invalid storage authorization request")
                    })?)
                    .await?,
            )
        }
        ("POST", "/libraries") => {
            let input: Account = serde_json::from_slice(&body)
                .map_err(|_| ResourceUnavailable("Invalid storage authorization request"))?;
            Reply::json(store.libraries(&input.id).await?)
        }
        ("POST", "/remove") => {
            let input: Account = serde_json::from_slice(&body)
                .map_err(|_| ResourceUnavailable("Invalid storage authorization request"))?;
            store.remove(&input.id).await?;
            Reply::json(true)
        }
        ("POST", "/poll") | ("POST", "/cancel") => {
            let input: Handle = serde_json::from_slice(&body)
                .map_err(|_| ResourceUnavailable("Invalid storage authorization request"))?;
            let resource = session.resource_value(&input.handle)?;
            let nextcloud = resource.clone().downcast::<Authorization>().ok();
            #[cfg(feature = "pro")]
            let oauth = resource.downcast::<oauth::Authorization>().ok();
            #[cfg(feature = "pro")]
            let valid_handle = nextcloud.is_some() || oauth.is_some();
            #[cfg(not(feature = "pro"))]
            let valid_handle = nextcloud.is_some();
            ensure!(
                valid_handle,
                ResourceUnavailable("Not a storage authorization handle")
            );
            if operation == "/cancel" {
                session.release(&input.handle);
                Reply::json(true)
            } else {
                let result = match nextcloud {
                    Some(resource) => store.poll(&resource).await?,
                    #[cfg(feature = "pro")]
                    None => oauth.unwrap().poll(store).await?,
                    #[cfg(not(feature = "pro"))]
                    None => unreachable!("validated authorization handle"),
                };
                if matches!(
                    result.get("status").and_then(Value::as_str),
                    Some("authorized" | "denied" | "failed" | "cancelled" | "expired")
                ) {
                    session.release(&input.handle);
                }
                Reply::json(result)
            }
        }
        _ => return Err(ResourceUnavailable("Unknown storage authorization operation").into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credential() -> Credential {
        Credential {
            id: "account_test_1234567890".into(),
            kind: Kind::Seafile,
            provider_account_id: "alice@example.test".into(),
            label: "Alice".into(),
            username: String::new(),
            server: "https://cloud.test".into(),
            access_token: "private-access".into(),
            expires_at: i64::MAX,
            broker_url: String::new(),
            broker_grant: String::new(),
            read_only: false,
            library_id: "libA".into(),
            requires_authorization: false,
        }
    }
    #[test]
    fn account_identity_generations_private_persistence_and_failed_writes_are_atomic() {
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        let initial = store.install(credential(), None).unwrap();
        assert!(!initial.to_string().contains("private-access"));
        let id = initial["id"].as_str().unwrap();
        let generation = store.state.lock().unwrap().generations[id].clone();
        let restored = Storage::load(root.path()).unwrap();
        assert_eq!(
            restored
                .credential("Seafile", "https://cloud.test", id, "libA")
                .unwrap()
                .access_token,
            "private-access"
        );
        assert!(
            restored
                .credential("Seafile", "https://other.test", id, "libA")
                .is_err()
        );
        assert!(
            restored
                .credential("Seafile", "https://cloud.test", id, "libB")
                .is_err()
        );
        assert!(
            restored
                .credential("Nextcloud", "https://cloud.test", id, "libA")
                .is_err()
        );
        let mut other = credential();
        other.provider_account_id = "other".into();
        assert!(store.install(other, Some(id)).is_err());
        assert_eq!(store.state.lock().unwrap().generations[id], generation);
        let mut updated = credential();
        updated.access_token = "new-private-access".into();
        store.install(updated, Some(id)).unwrap();
        assert_ne!(store.state.lock().unwrap().generations[id], generation);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::rename(&store.path, root.path().join("before.json")).unwrap();
        std::fs::create_dir(&store.path).unwrap();
        let mut update = credential();
        update.label = "Uncommitted".into();
        assert!(store.install(update, Some(id)).is_err());
        assert_eq!(store.accounts()[0]["label"], "Alice");
        assert!(
            std::fs::read_dir(root.path()).unwrap().all(|p| !p
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
        for server in [
            "ftp://cloud.test",
            "https://user:password@cloud.test",
            "https://cloud.test/?token=secret",
            "https://cloud.test/#fragment",
        ] {
            assert!(canonical_server(server).is_err());
        }
        assert!(
            scoped_login_url("https://cloud.test/nc", "https://cloud.test/nc-alias/poll").is_err()
        );
        assert!(scoped_login_url("https://cloud.test/nc", "https://other.test/nc/poll").is_err());
        assert!(
            scoped_login_url("https://cloud.test/nc", "https://user@cloud.test/nc/poll").is_err()
        );
    }
    #[test]
    fn plaintext_preview_state_is_upgraded_without_losing_credentials_and_ciphertext_fails_closed()
    {
        let root = tempfile::tempdir().unwrap();
        let mut state = State::default();
        let c = credential();
        let id = c.id.clone();
        state.accounts.insert(id.clone(), c);
        let path = root.path().join("storage-accounts.json");
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        let store = Storage::load(root.path()).unwrap();
        assert_eq!(store.metadata(&id).unwrap().access_token, "private-access");
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert!(!bytes.windows(14).any(|v| v == b"private-access"));
        drop(store);
        assert_eq!(
            Storage::load(root.path())
                .unwrap()
                .metadata(&id)
                .unwrap()
                .access_token,
            "private-access"
        );
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &altered).unwrap();
        assert!(Storage::load(root.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), altered);
        std::fs::write(&path, &bytes).unwrap();
        let key = root.path().join("storage-account-key.bin");
        std::fs::remove_file(&key).unwrap();
        assert!(Storage::load(root.path()).is_err());
        assert!(!key.exists());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    #[tokio::test]
    async fn expired_authorizations_release_the_global_slot_and_session_handle() {
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        let session = Session::new(root.path()).unwrap();
        let slot = Arc::new(Mutex::new(Some(
            store.pending.clone().try_acquire_owned().unwrap(),
        )));
        let cancel = CancellationToken::new();
        let close = cancel.clone();
        let slot_close = slot.clone();
        let resource = Authorization {
            state: AsyncMutex::new(Some(Pending {
                server: "https://cloud.test".into(),
                endpoint: "https://cloud.test/poll".into(),
                token: "private-poll".into(),
                expires: 0,
                replace: None,
            })),
            cancel,
            slot,
        };
        let handle = session
            .own_with_close(resource, move || {
                close.cancel();
                slot_close.lock().unwrap().take();
            })
            .unwrap();
        assert_eq!(store.pending.available_permits(), 31);
        let reply = handle_request(&session, &store, &handle).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.body).unwrap()["status"],
            "expired"
        );
        assert!(session.resource::<Authorization>(&handle).is_err());
        assert_eq!(store.pending.available_permits(), 32);
        let wrong = session.own(7u8).unwrap();
        let wrong = super::handle(
            "POST",
            "/api/web-ui/platform/storage/poll",
            serde_json::to_vec(&json!({"handle":wrong})).unwrap(),
            &session,
            &store,
        )
        .await
        .unwrap_err();
        assert_eq!(Reply::from_error(wrong).status, 409);
        let missing = super::handle(
            "POST",
            "/api/web-ui/platform/storage/poll",
            serde_json::to_vec(&json!({"handle":"missing"})).unwrap(),
            &session,
            &store,
        )
        .await
        .unwrap_err();
        assert_eq!(Reply::from_error(missing).status, 400);
    }
    async fn handle_request(session: &Arc<Session>, store: &Arc<Storage>, id: &str) -> Reply {
        handle(
            "POST",
            "/api/web-ui/platform/storage/poll",
            serde_json::to_vec(&json!({"handle":id})).unwrap(),
            session,
            store,
        )
        .await
        .unwrap()
    }
}

#[cfg(test)]
mod upload_owner_tests {
    use super::*;
    #[cfg(not(feature = "pro"))]
    #[test]
    fn standard_edition_rejects_official_storage_accounts() {
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        for protocol in ["GoogleDrive", "Dropbox"] {
            let error = store.credential(protocol, "", "", "").err().unwrap();
            assert_eq!(Reply::from_error(error).status, 409);
        }
    }

    #[test]
    fn upload_owner_is_private_stable_state_and_atomic_on_failed_write() {
        let directory = tempfile::tempdir().unwrap();
        let store = Storage::load(directory.path()).unwrap();
        let owner = store.upload_owner().unwrap();
        assert_eq!(owner.len(), 36);
        assert_eq!(store.upload_owner().unwrap(), owner);
        let bytes = std::fs::read(directory.path().join("storage-accounts.json")).unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert!(!bytes.windows(owner.len()).any(|b| b == owner.as_bytes()));
        drop(store);
        assert_eq!(
            Storage::load(directory.path())
                .unwrap()
                .upload_owner()
                .unwrap(),
            owner
        );
        let broken = tempfile::tempdir().unwrap();
        let store = Storage::load(broken.path()).unwrap();
        std::fs::create_dir(broken.path().join("storage-accounts.json")).unwrap();
        assert!(store.upload_owner().is_err());
        assert!(store.state.lock().unwrap().upload_owner.is_empty());
    }
}
