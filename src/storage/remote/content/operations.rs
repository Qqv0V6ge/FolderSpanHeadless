use super::{
    Client, Config, Content, Location, Path, Request, cloud_text, location, owner, readonly, scope,
};
use super::{logical::Logical, vault::Vault};
use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
    },
    storage::{
        accounts::Storage,
        content_crypto::{ContentError, ErrorCode},
    },
};
use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(super) struct Operation<'a> {
    pub config: &'a Config,
    pub store: &'a Arc<Storage>,
    pub session: &'a Arc<Session>,
    pub cancel: &'a CancellationToken,
}
impl Operation<'_> {
    fn inside(&self, path: &Path) -> Result<bool> {
        let Some(reference) = location(self.config)? else {
            return Ok(false);
        };
        scope(self.config)?;
        let root = reference.root.path.trim_end_matches('/');
        Ok(path
            .reference
            .as_ref()
            .and_then(|r| r.get("content"))
            .and_then(|r| r.get("vaultId"))
            .and_then(Value::as_str)
            == Some(reference.vault_id.as_str())
            || path.path == if root.is_empty() { "/" } else { root }
            || path.path.starts_with(&(root.to_owned() + "/")))
    }
    fn client(&self) -> Result<Client> {
        Client::create(self.config, Some(self.store), self.session, "")
    }
    fn credentials(
        &self,
        client: &Client,
        state: &Content,
        reference: &Location,
        write: bool,
    ) -> Result<(String, Zeroizing<[u8; 32]>)> {
        if write && (client.capabilities()["write"] != true || readonly(self.config)) {
            return Err(ContentError(ErrorCode::ReadOnly, "this location is read-only").into());
        }
        let owner = owner(self.store, self.config, &reference.root)?;
        let key = state.keys.key(&scope(self.config)?, &owner)?;
        Ok((owner, key))
    }
    async fn no_legacy_manifest(&self) -> Result<()> {
        if !matches!(self.config.protocol.as_str(), "Dropbox" | "Nextcloud") {
            return Ok(());
        }
        let present = match self.client()? {
            #[cfg(feature = "pro")]
            Client::OfficialCloud(client) => client.content_manifest_exists().await?,
            Client::Nextcloud(client) => client.content_manifest_exists().await?,
            _ => false,
        };
        ensure!(
            !present,
            ResourceUnavailable(
                "authenticated content classification requires its recovery backup"
            )
        );
        Ok(())
    }
    pub async fn handle(&self, op: &str, input: &Request, state: &mut Content) -> Result<Reply> {
        match op {
            "prepare" => return self.prepare(input, state).await,
            "begin" => return self.begin(input, state).await,
            "record" => return self.record(input, state).await,
            "publish" => return self.publish(input, state).await,
            "upload-encryption" => {
                let task = state.stages.task(self.store, input, true)?;
                let enabled = if let Some(reference) = location(self.config)? {
                    self.spool(input, task)?.is_some() || reference.enabled
                } else {
                    false
                };
                return Ok(Reply::json(enabled));
            }
            _ => {}
        }
        ensure!(
            matches!(
                op,
                "logical"
                    | "list"
                    | "resolve-download"
                    | "rename"
                    | "delete"
                    | "mkdir"
                    | "mutation"
                    | "upload-target"
            ),
            ResourceUnavailable("unknown content operation")
        );
        let reference = location(self.config)?;
        let file = input.file.as_ref();
        let path = if matches!(op, "logical" | "resolve-download") {
            let file = file.context("content file required")?;
            Path {
                path: file.path.clone(),
                reference: file.storage_reference.clone(),
            }
        } else {
            input.target.clone().context("content target required")?
        };
        let inside = self.inside(&path)?;
        if op == "rename" {
            let destination = input
                .destination
                .as_ref()
                .context("content destination required")?;
            let destination_inside = self.inside(destination)?;
            if inside || destination_inside {
                ensure!(
                    inside && destination_inside,
                    ResourceUnavailable("cross-location moves require a verified content copy")
                );
            }
        }
        if op == "mutation" {
            if !inside {
                if reference.is_none() && !cloud_text(self.config, "connectionId").trim().is_empty()
                {
                    self.no_legacy_manifest().await?;
                }
                return Ok(Reply::json(true));
            }
        } else if !inside {
            return Ok(if op == "upload-target" {
                Reply::json(path)
            } else {
                Reply::json(Value::Null)
            });
        }
        let reference = reference.context("password location missing")?;
        let write = matches!(
            op,
            "rename" | "delete" | "mkdir" | "upload-target" | "mutation"
        );
        let client = self.client()?;
        let (owner, key) = self.credentials(&client, state, &reference, write)?;
        let vault = Vault::new(&client, &reference.root, self.store, &owner, self.cancel)?;
        let logical = Logical::new(&client, &reference, &vault, &key);
        match op {
            "list" => Ok(Reply::json(logical.list(&path).await?)),
            "logical" => {
                let entry = logical.stat(&path).await?.ok_or(PlatformFailure)?;
                let mut file = file.context("content file required")?.clone();
                file.name = entry.name;
                file.path = entry.path;
                file.is_directory = entry.is_directory;
                file.is_hidden = entry.is_hidden;
                file.size = entry.size;
                file.created_date = entry.created_date;
                file.updated_date = entry.updated_date;
                file.is_symbolic_link = entry.is_symbolic_link;
                file.is_symbolic_link_known = entry.is_symbolic_link_known;
                file.storage_reference = entry.reference;
                Ok(Reply::json(file))
            }
            "resolve-download" => {
                let (file, target, size) = logical
                    .resolve_download(file.context("content file required")?)
                    .await?;
                Ok(Reply::json(
                    json!({"file":file,"target":target,"size":size}),
                ))
            }
            "rename" => Ok(Reply::json(
                logical
                    .rename(
                        &path,
                        input
                            .destination
                            .as_ref()
                            .context("content destination required")?,
                    )
                    .await?,
            )),
            "delete" => Ok(Reply::json(
                logical.delete(&path, input.is_directory).await?,
            )),
            "mkdir" => Ok(Reply::json(logical.mkdir(&path, reference.enabled).await?)),
            "upload-target" => Ok(Reply::json(logical.ordinary_upload(&path).await?)),
            "mutation" => {
                vault.history(&reference.vault_id, &key, true).await?;
                Ok(Reply::json(true))
            }
            _ => Err(ResourceUnavailable("unknown content operation").into()),
        }
    }
}

const SPOOL_PREFIX: &str = "auth.storage.password-location.spool.";
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spool {
    #[serde(default = "super::version")]
    version: i32,
    task_key: i64,
    entry_id: String,
    vault_id: String,
    source_identity: String,
    source_digest: String,
    path: String,
    size: i64,
    source_size: i64,
    source_updated_date: i64,
    cipher_digest: String,
    object_id: String,
    operation_id: String,
    #[serde(default)]
    target: Option<Path>,
    #[serde(default)]
    record: Option<crate::storage::content_history::Commit>,
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    publication_started: bool,
}
fn cancelled(cancel: &CancellationToken) -> Result<()> {
    ensure!(
        !cancel.is_cancelled(),
        ResourceUnavailable("content operation cancelled")
    );
    Ok(())
}
fn hash_file(mut file: std::fs::File, cancel: &CancellationToken) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut bytes = Zeroizing::new(vec![0; 64 * 1024]);
    loop {
        cancelled(cancel)?;
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
async fn digest_file(
    file: std::fs::File,
    cancel: &CancellationToken,
    work: &Arc<tokio::sync::Mutex<()>>,
) -> Result<String> {
    let cancel = cancel.clone();
    let work = work.clone().lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let _work = work;
        hash_file(file, &cancel)
    })
    .await
    .map_err(|_| PlatformFailure)?
}

fn remove_cipher(path: &std::path::Path) -> Result<()> {
    let (parent, name, _) = crate::storage::files::open_parent_nofollow(path)?;
    parent.remove_file(name)?;
    Ok(())
}
impl Operation<'_> {
    fn spool_name(&self, input: &Request, task: i64) -> Result<String> {
        use sha2::{Digest, Sha256};
        let reference = location(self.config)?.context("password location missing")?;
        let value = super::authorization_owner(self.config, &reference.root)?
            + &serde_json::to_string(&[
                task.to_string(),
                input.entry_id.clone(),
                scope(self.config)?,
            ])?;
        Ok(SPOOL_PREFIX.to_owned() + &hex::encode(Sha256::digest(value.as_bytes())))
    }
    fn spool(&self, input: &Request, task: i64) -> Result<Option<Spool>> {
        let Some(value) = self.store.content_setting(&self.spool_name(input, task)?) else {
            return Ok(None);
        };
        let damaged = || {
            ContentError(
                ErrorCode::DamagedLocation,
                "protected content upload recovery data is invalid",
            )
        };
        let value: Spool = serde_json::from_str(&value).map_err(|_| damaged())?;
        ensure!(
            value.version == 1
                && value.task_key == task
                && value.entry_id == input.entry_id
                && Some(value.vault_id.as_str())
                    == location(self.config)?.as_ref().map(|r| r.vault_id.as_str()),
            damaged()
        );
        Ok(Some(value))
    }
    fn save_spool(&self, input: &Request, spool: &Spool) -> Result<()> {
        let name = self.spool_name(input, spool.task_key)?;
        let value = Zeroizing::new(serde_json::to_string(spool)?);
        self.store.content_transaction(|settings| {
            settings.insert(name, value);
            Ok(())
        })
    }
    async fn prepare(&self, input: &Request, state: &mut Content) -> Result<Reply> {
        let task = state.stages.task(self.store, input, false)?;
        input.file.as_ref().context("content file required")?;
        ensure!(
            state.stages.is_plain(task, &input.staged_path),
            "unknown private content stage"
        );
        state.stages.identity(task, &input.staged_path)?;
        let result = self.prepare_inner(input, state, task).await;
        state.stages.remove_plain(task, &input.staged_path)?;
        result
    }
    async fn prepare_inner(
        &self,
        input: &Request,
        state: &mut Content,
        task: i64,
    ) -> Result<Reply> {
        let source = input.file.as_ref().context("content source required")?;
        let Some(reference) = location(self.config)? else {
            return Ok(Reply::json(Value::Null));
        };
        let previous = self.spool(input, task)?;
        if !reference.enabled && previous.is_none() {
            return Ok(Reply::json(Value::Null));
        }
        let client = self.client()?;
        let (owner, key) = self.credentials(&client, state, &reference, true)?;
        let vault = Vault::new(&client, &reference.root, self.store, &owner, self.cancel)?;
        let stage = state.stages.open(task, &input.staged_path, false)?;
        let source_size = stage.metadata()?.len();
        let source_digest = digest_file(stage, self.cancel, &state.work).await?;
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Source<'a> {
            protocol: super::Protocol,
            protocol_id: &'a str,
            path: &'a str,
            storage_reference: Option<Value>,
        }
        let source_identity = serde_json::to_string(&Source {
            protocol: source.protocol,
            protocol_id: &source.protocol_id,
            path: &source.path,
            storage_reference: source
                .storage_reference
                .as_ref()
                .map(crate::storage::remote::reference_defaults),
        })?;
        if let Some(mut saved) = previous {
            let history = vault.history(&reference.vault_id, &key, false).await?;
            let remote = history.records().get(&saved.operation_id);
            if let Some(remote) = remote {
                ensure!(
                    Some(remote) == saved.record.as_ref(),
                    ResourceUnavailable("content operation identity changed")
                );
            }
            if saved.source_identity != source_identity || saved.source_digest != source_digest {
                ensure!(
                    saved.record.is_none() && remote.is_none(),
                    ContentError(
                        ErrorCode::SourceChanged,
                        "source changed during an interrupted write; preserve the original operation"
                    )
                );
            } else {
                let committed = remote.is_some();
                let uploaded = vault
                    .object_matches(&saved.object_id, saved.size, &saved.cipher_digest)
                    .await?;
                ensure!(
                    !(committed || saved.publication_started) || uploaded,
                    ContentError(
                        ErrorCode::DamagedLocation,
                        "a published immutable object is missing or changed"
                    )
                );
                if committed {
                    saved.completed = true;
                    self.save_spool(input, &saved)?;
                } else if !uploaded {
                    let path = state.stages.cipher_path(task, &saved.path)?;
                    let cipher = super::stages::raw_file(&path, false)?;
                    ensure!(
                        cipher.metadata()?.len() == saved.size as u64
                            && digest_file(cipher, self.cancel, &state.work).await?
                                == saved.cipher_digest,
                        ResourceUnavailable("encrypted upload spool changed")
                    );
                }
                state.stages.revoke_cipher(task, &input.entry_id);
                if !uploaded && !committed {
                    state
                        .stages
                        .remember_cipher(task, &input.entry_id, &saved.path)?;
                }
                return Ok(Reply::json(
                    json!({"path":if uploaded||committed{""}else{&saved.path},"size":saved.size,
                    "sourceVersion":source_digest,"target":vault.object_path(&saved.object_id).await?,
                    "uploaded":uploaded,"committed":committed}),
                ));
            }
            remove_cipher(&state.stages.cipher_path(task, &saved.path)?)?;
        }
        vault
            .authenticate_location(&reference.vault_id, &key)
            .await?;
        let object_id = super::new_uuid()?;
        let (path, cipher) = state.stages.new_cipher(task)?;
        let stage = state.stages.open(task, &input.staged_path, false)?;
        let object_scope =
            crate::storage::content_history::object_scope(&reference.vault_id, &object_id)?;
        let cancel = self.cancel.clone();
        let cipher_key = key.clone();
        let work = state.work.clone().lock_owned().await;
        let outcome = tokio::task::spawn_blocking(move || -> Result<(i64, String)> {
            let _work = work;
            let mut stage = stage;
            let mut cipher = cipher;
            crate::storage::content_crypto::encrypt(
                &mut stage,
                &mut cipher,
                &cipher_key,
                &object_scope,
                || cancelled(&cancel),
            )?;
            cipher.sync_all()?;
            let digest = hash_file(cipher.try_clone()?, &cancel)?;
            let size = i64::try_from(cipher.metadata()?.len())?;
            drop(cipher);
            drop(stage);
            Ok((size, digest))
        })
        .await
        .map_err(|_| anyhow::Error::from(PlatformFailure))
        .and_then(|v| v);
        let result = match outcome {
            Ok((cipher_size, cipher_digest)) => {
                let saved = Spool {
                    version: 1,
                    task_key: task,
                    entry_id: input.entry_id.clone(),
                    vault_id: reference.vault_id.clone(),
                    source_identity,
                    source_digest: source_digest.clone(),
                    path: path.to_string_lossy().into_owned(),
                    size: cipher_size,
                    source_size: i64::try_from(source_size)?,
                    source_updated_date: source.updated_date.max(0),
                    cipher_digest,
                    object_id: object_id.clone(),
                    operation_id: super::new_uuid()?,
                    target: None,
                    record: None,
                    completed: false,
                    publication_started: false,
                };
                match self.save_spool(input, &saved) {
                    Ok(()) => Ok(saved),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let saved = match result {
            Ok(value) => value,
            Err(error) => {
                remove_cipher(&path)?;
                return Err(error);
            }
        };
        state.stages.revoke_cipher(task, &input.entry_id);
        state
            .stages
            .remember_cipher(task, &input.entry_id, &saved.path)?;
        Ok(Reply::json(
            json!({"path":saved.path,"size":saved.size,"sourceVersion":source_digest,
            "target":vault.object_path(&object_id).await?,"uploaded":false,"committed":false}),
        ))
    }
    async fn begin(&self, input: &Request, state: &mut Content) -> Result<Reply> {
        let task = state.stages.task(self.store, input, true)?;
        let target = input.target.as_ref().context("content target required")?;
        let Some(reference) = location(self.config)? else {
            if !cloud_text(self.config, "connectionId").trim().is_empty() {
                self.no_legacy_manifest().await?;
            }
            return Ok(Reply::json(true));
        };
        let saved = self.spool(input, task)?;
        if !self.inside(target)? {
            ensure!(
                saved.is_none(),
                ResourceUnavailable("prepared content cannot leave its password location")
            );
            return Ok(Reply::json(true));
        }
        let client = self.client()?;
        let (owner, key) = self.credentials(&client, state, &reference, true)?;
        let vault = Vault::new(&client, &reference.root, self.store, &owner, self.cancel)?;
        let logical = Logical::new(&client, &reference, &vault, &key);
        let Some(mut saved) = saved else {
            ensure!(
                !reference.enabled,
                ResourceUnavailable("encrypted upload spool missing")
            );
            logical.ordinary_upload(target).await?;
            return Ok(Reply::json(true));
        };
        ensure!(
            saved
                .target
                .as_ref()
                .is_none_or(|p| p.path == target.path && p.reference == target.reference),
            ResourceUnavailable("encrypted upload destination changed")
        );
        if let Some(record) = &saved.record {
            let history = vault.history(&saved.vault_id, &key, false).await?;
            if let Some(remote) = history.records().get(&record.operation_id) {
                ensure!(
                    remote == record,
                    ResourceUnavailable("content operation identity changed")
                );
                vault.verify_object(record).await?;
                saved.completed = true;
                self.save_spool(input, &saved)?;
            }
            return Ok(Reply::json(true));
        }
        let cipher = super::stages::raw_file(&state.stages.cipher_path(task, &saved.path)?, false)?;
        ensure!(
            digest_file(cipher, self.cancel, &state.work).await? == saved.cipher_digest,
            ResourceUnavailable("encrypted upload spool changed")
        );
        let record = logical
            .prepare_file(
                target,
                super::logical::PreparedFile {
                    operation_id: &saved.operation_id,
                    object_id: &saved.object_id,
                    ciphertext_length: saved.size,
                    ciphertext_digest: &saved.cipher_digest,
                    size: saved.source_size,
                    updated_date: saved.source_updated_date,
                },
            )
            .await?;
        saved.target = Some(target.clone());
        saved.record = Some(record);
        self.save_spool(input, &saved)?;
        Ok(Reply::json(true))
    }
    async fn record(&self, input: &Request, state: &mut Content) -> Result<Reply> {
        ensure!(
            state.stages.known_task(input.task_key),
            "unknown content encryption task"
        );
        let task = state.stages.task(self.store, input, false)?;
        let entry = input
            .entry
            .as_ref()
            .context("content upload result required")?;

        let reference =
            location(self.config)?.context(ResourceUnavailable("password location missing"))?;
        let client = self.client()?;
        let (owner, key) = self.credentials(&client, state, &reference, true)?;
        let vault = Vault::new(&client, &reference.root, self.store, &owner, self.cancel)?;
        let mut saved = self.spool(input, task)?.context(ResourceUnavailable(
            "encrypted upload recovery data missing",
        ))?;
        let record = saved.record.clone().context(ResourceUnavailable(
            "encrypted upload has no logical destination",
        ))?;
        let target = vault.object_path(&saved.object_id).await?;
        ensure!(
            entry.path == target.path
                && entry.size == saved.size
                && !entry.is_directory
                && !entry.is_symbolic_link,
            ResourceUnavailable("encrypted upload result does not match its immutable object")
        );
        saved.publication_started = true;
        self.save_spool(input, &saved)?;
        vault.publish(&record, &key).await?;
        saved.completed = true;
        self.save_spool(input, &saved)?;
        Ok(Reply::json(true))
    }
    async fn publish(&self, input: &Request, state: &mut Content) -> Result<Reply> {
        let task = state.stages.task(self.store, input, false)?;
        input.file.as_ref().context("content file required")?;
        ensure!(
            state.stages.is_plain(task, &input.staged_path),
            "unknown private content stage"
        );
        state.stages.identity(task, &input.staged_path)?;
        let result = self.publish_inner(input, state, task).await;
        state.stages.remove_plain(task, &input.staged_path)?;
        result
    }
    async fn publish_inner(
        &self,
        input: &Request,
        state: &mut Content,
        task: i64,
    ) -> Result<Reply> {
        let file = input.file.as_ref().context("content file required")?;
        let destination = super::stages::normalized(std::path::Path::new(&input.destination_path))?;
        let destination = destination
            .to_str()
            .context("invalid content destination")?
            .to_owned();
        if state.stages.registered_plain(&destination) {
            ensure!(
                state.stages.is_plain(task, &destination),
                "content destination belongs to another task"
            );
            state.stages.identity(task, &destination)?;
        } else {
            state
                .files
                .check_write(std::path::Path::new(&destination), self.session)?;
        }
        let mut stage = state.stages.open(task, &input.staged_path, false)?;
        let path = Path {
            path: file.path.clone(),
            reference: file.storage_reference.clone(),
        };
        let mut decrypt = None;
        if let Some(reference) = location(self.config)? {
            if self.inside(&path)? {
                let client = self.client()?;
                let (owner, key) = self.credentials(&client, state, &reference, false)?;
                let vault = Vault::new(&client, &reference.root, self.store, &owner, self.cancel)?;
                let identity = file
                    .storage_reference
                    .as_ref()
                    .and_then(|r| r.get("content"))
                    .filter(|v| !v.is_null());
                let managed = identity.is_some_and(|v| {
                    v["vaultId"] == reference.vault_id
                        && v["ordinaryPath"].as_str().unwrap_or("").is_empty()
                });
                if managed {
                    let history = vault.history(&reference.vault_id, &key, false).await?;
                    let identity = identity.unwrap();
                    let record = history
                        .records()
                        .get(identity["revisionId"].as_str().unwrap_or(""))
                        .ok_or(ContentError(
                            ErrorCode::DamagedLocation,
                            "authenticated content revision missing",
                        ))?;
                    ensure!(
                        identity["entryId"] == record.entry_id
                            && record.kind == crate::storage::content_history::Kind::File
                            && record.size == file.size
                            && record.ciphertext_length == i64::try_from(stage.metadata()?.len())?
                            && digest_file(stage.try_clone()?, self.cancel, &state.work).await?
                                == record.ciphertext_digest,
                        ResourceUnavailable("managed content is damaged or changed")
                    );
                    use std::io::{Seek, SeekFrom};
                    stage.seek(SeekFrom::Start(0))?;
                    decrypt = Some((
                        key,
                        crate::storage::content_history::object_scope(
                            &reference.vault_id,
                            &record.object_id,
                        )?,
                    ));
                } else {
                    let logical = Logical::new(&client, &reference, &vault, &key);
                    let (classified, _, _) = logical.resolve_download(file).await?;
                    ensure!(
                        classified
                            .storage_reference
                            .as_ref()
                            .and_then(|r| r.get("content"))
                            .and_then(|c| c.get("ordinaryPath"))
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty()),
                        ResourceUnavailable(
                            "ordinary file requires authenticated directory classification"
                        )
                    );
                }
            }
        } else {
            if !cloud_text(self.config, "connectionId").trim().is_empty() {
                self.no_legacy_manifest().await?;
            }
            use std::io::{Read, Seek, SeekFrom};
            let mut prefix = [0; 8];
            let count = stage.read(&mut prefix)?;
            stage.seek(SeekFrom::Start(0))?;
            if count == 8 && &prefix == b"FSPANENC" {
                scope(self.config)?;
                return Err(
                    ResourceUnavailable("content encryption is locked; recover its key").into(),
                );
            }
        }
        let cancel = self.cancel.clone();
        let target = destination.clone();
        let work = state.work.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _work = work;
            let mut stage = stage;
            let result = super::stages::publish_private(
                &mut stage,
                std::path::Path::new(&target),
                decrypt,
                &cancel,
            );
            drop(stage);
            result
        })
        .await
        .map_err(|_| PlatformFailure)??;
        state.stages.refresh_destination(task, &destination)?;
        Ok(Reply::json(true))
    }
}
