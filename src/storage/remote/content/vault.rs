use super::{Client, Path};
use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::{
        accounts::Storage,
        content_crypto::{self, ContentError, ErrorCode},
        content_history::{self, Commit, History, Kind, MAX_RECORDS},
        remote::{DownloadPart, Entry, nextcloud::METADATA_BATCH_SIZE},
    },
};
use anyhow::{Context as _, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::AtomicU64},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(super) const NAMESPACE: &str = ".folderspan-vault";
const METADATA_LIMIT: usize = 64 * 1024 + 48;
fn unavailable(message: &'static str) -> anyhow::Error {
    ResourceUnavailable(message).into()
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn version() -> u32 {
    1
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    #[serde(default = "version")]
    version: u32,
    records: BTreeMap<String, String>,
}
struct Scan {
    directory: Option<Path>,
    entries: Vec<Entry>,
}
impl Scan {
    fn candidates(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.name.ends_with(".location"))
            .collect()
    }
    fn roots(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.name.ends_with(".root"))
            .collect()
    }
    fn unique(&self, expected: Option<&str>) -> Result<()> {
        let candidates = self.candidates();
        let roots = self.roots();
        let identities: std::collections::BTreeSet<_> = candidates
            .iter()
            .chain(&roots)
            .map(|e| e.name.rsplit_once('.').unwrap().0)
            .collect();
        if candidates.len() > 1
            || roots.len() > 1
            || identities.len() > 1
            || expected.is_some_and(|id| identities.iter().any(|value| *value != id))
        {
            return Err(ContentError(
                ErrorCode::InitializationConflict,
                "multiple password locations were found; preserve all initialization candidates",
            )
            .into());
        }
        Ok(())
    }
}
pub(super) struct Vault<'a> {
    client: &'a Client,
    pub root: &'a Path,
    store: &'a Arc<Storage>,
    pending_name: String,
    cancel: &'a CancellationToken,
}
impl<'a> Vault<'a> {
    pub fn new(
        client: &'a Client,
        root: &'a Path,
        store: &'a Arc<Storage>,
        owner: &str,
        cancel: &'a CancellationToken,
    ) -> Result<Self> {
        crate::storage::remote::validate_write_path(&root.path)?;
        ensure!(
            root.path.starts_with('/')
                && !root
                    .path
                    .split('/')
                    .any(|p| matches!(p, NAMESPACE | ".folderspan-content.json"))
                && root
                    .reference
                    .as_ref()
                    .is_none_or(|r| r.get("content").is_none_or(serde_json::Value::is_null)),
            ContentError(
                ErrorCode::DamagedLocation,
                "reserved location material cannot be used as a root"
            )
        );
        let pending_name = "auth.storage.password-location.pending.".to_owned()
            + &digest((owner.to_owned() + &super::minimal_path(root)?).as_bytes());
        Ok(Self {
            client,
            root,
            store,
            pending_name,
            cancel,
        })
    }
    async fn scan(&self) -> Result<Scan> {
        ensure!(
            !self.cancel.is_cancelled(),
            unavailable("content context closed")
        );
        let entries = self
            .client
            .list(&self.root.path, self.root.reference.as_ref())
            .await
            .context("list password root")?;
        let names: std::collections::BTreeSet<_> =
            entries.iter().map(|e| e.name.as_str()).collect();
        if entries.iter().any(|e| {
            e.name.ends_with(".location")
                && internal_name(&e.name)
                && names
                    .contains((e.name.trim_end_matches(".location").to_owned() + ".root").as_str())
        }) {
            return Err(ContentError(
                ErrorCode::DamagedLocation,
                "this root exposes password location internals",
            )
            .into());
        }
        ensure!(
            !names.contains(".folderspan-content.json"),
            unavailable("unsupported previous encrypted metadata is present")
        );
        let directories: Vec<_> = entries.iter().filter(|e| e.name == NAMESPACE).collect();
        ensure!(
            directories.len() <= 1,
            unavailable("ambiguous password location namespace")
        );
        let Some(directory) = directories.first() else {
            return Ok(Scan {
                directory: None,
                entries: Vec::new(),
            });
        };
        ensure!(
            directory.is_directory && !directory.is_symbolic_link,
            unavailable("password namespace is not a safe directory")
        );
        let path = child(self.root, directory);
        let children = self
            .client
            .list(&path.path, path.reference.as_ref())
            .await
            .context("list password namespace")?;
        let names: std::collections::BTreeSet<_> = children.iter().map(|e| &e.name).collect();
        ensure!(
            names.len() == children.len(),
            unavailable("duplicate password metadata names")
        );
        for entry in &children {
            ensure!(
                !entry.is_directory && !entry.is_symbolic_link && internal_name(&entry.name),
                unavailable("unknown password location material")
            );
            content_crypto::canonical_uuid(entry.name.rsplit_once('.').unwrap().0)?;
        }
        Ok(Scan {
            directory: Some(path),
            entries: children,
        })
    }
    async fn bytes(&self, scan: &Scan, entry: &Entry, limit: usize) -> Result<Vec<u8>> {
        ensure!(
            entry.size >= 0 && entry.size <= limit as i64,
            "password metadata exceeds its bounded format"
        );
        let path = child(
            scan.directory
                .as_ref()
                .ok_or_else(|| unavailable("password directory missing"))?,
            entry,
        );
        let bytes = read_bytes(self.client, &path, entry.size, limit, self.cancel)
            .await
            .context("read password metadata")?;
        ensure!(
            bytes.len() as i64 == entry.size,
            unavailable("password metadata changed length")
        );
        Ok(bytes)
    }
    async fn metadata_batch(
        &self,
        scan: &Scan,
        entries: &[&Entry],
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let Client::Nextcloud(client) = self.client else {
            return Ok(BTreeMap::new());
        };
        let directory = scan
            .directory
            .as_ref()
            .context("password directory missing")?;
        let batch = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(unavailable("content context closed")),
            result = client.download_content_metadata(&directory.path, directory.reference.as_ref(), entries, METADATA_LIMIT) => result?,
        };
        Ok(batch.unwrap_or_default())
    }
    async fn metadata_bytes(
        &self,
        scan: &Scan,
        entry: &Entry,
        limit: usize,
        batch: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        if let Some(bytes) = batch.remove(&entry.name) {
            ensure!(
                bytes.len() <= limit,
                "password metadata exceeds its bounded format"
            );
            return Ok(bytes);
        }
        self.bytes(scan, entry, limit).await
    }
    async fn create_directory(&self) -> Result<Path> {
        let path = super::child_path(self.root, NAMESPACE)?;
        let created = self
            .client
            .mutate(
                "/mkdir",
                &path.path,
                "",
                true,
                path.reference.as_ref(),
                None,
            )
            .await;
        if let Some(directory) = self.scan().await?.directory {
            return Ok(directory);
        }
        created?;
        Err(unavailable(
            "password directory creation could not be verified",
        ))
    }
    async fn write_immutable(
        &self,
        directory: &Path,
        name: &str,
        bytes: &[u8],
        vault_id: &str,
    ) -> Result<()> {
        let before = self.scan().await?;
        before.unique(Some(vault_id))?;
        if let Some(entry) = before.entries.iter().find(|e| e.name == name) {
            ensure!(
                self.bytes(&before, entry, bytes.len()).await? == bytes,
                unavailable(
                    "existing initialization material differs; preserve it instead of overwriting"
                )
            );
            return Ok(());
        }
        let path = super::child_path(directory, name)?;
        upload_bytes(self.client, &path, bytes, self.cancel)
            .await
            .context("upload immutable password material")?;
        let after = self.scan().await?;
        after.unique(Some(vault_id))?;
        let entry = after
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| unavailable("password location publication is not visible"))?;
        ensure!(
            self.bytes(&after, entry, bytes.len()).await? == bytes,
            unavailable("password publication changed or was truncated")
        );
        Ok(())
    }
    pub async fn inspect(&self, known: &str) -> Result<Option<String>> {
        let current = self.scan().await?;
        current.unique(None)?;
        let candidates = current.candidates();
        if candidates.is_empty() {
            if !known.is_empty() {
                return Err(ContentError(
                    ErrorCode::DamagedLocation,
                    "known password location metadata is missing",
                )
                .into());
            }
            if !current.entries.is_empty() {
                let pending = self
                    .store
                    .content_setting(&self.pending_name)
                    .map(|v| STANDARD.decode(v.as_bytes()))
                    .transpose()?;
                let pending_id = pending
                    .as_deref()
                    .map(content_crypto::password_location_id)
                    .transpose()?;
                if pending_id.as_ref().is_none_or(|id| {
                    current
                        .entries
                        .iter()
                        .any(|e| e.name != id.to_owned() + ".root")
                }) {
                    return Err(ContentError(
                        ErrorCode::DamagedLocation,
                        "incomplete password location material is present",
                    )
                    .into());
                }
            }
            return Ok(None);
        }
        let candidate = candidates[0];
        let descriptor = self.bytes(&current, candidate, 124).await?;
        let id = content_crypto::password_location_id(&descriptor)?;
        let roots = current.roots();
        let root = roots.iter().find(|e| e.name == id.clone() + ".root");
        if candidate.name != id.clone() + ".location"
            || !known.is_empty() && known != id
            || root.is_none_or(|e| !(48..=METADATA_LIMIT as i64).contains(&e.size))
        {
            return Err(ContentError(
                ErrorCode::DamagedLocation,
                "password root or identity is missing or changed",
            )
            .into());
        }
        Ok(Some(id))
    }
    pub async fn initialize_or_unlock(
        &self,
        password: &str,
        known: &str,
    ) -> Result<(String, Zeroizing<[u8; 32]>)> {
        let initial = self.scan().await?;
        let pending = self
            .store
            .content_setting(&self.pending_name)
            .map(|v| STANDARD.decode(v.as_bytes()))
            .transpose()?;
        let pending_id = pending
            .as_deref()
            .map(content_crypto::password_location_id)
            .transpose()?;
        initial.unique(pending_id.as_deref())?;
        if !initial.candidates().is_empty() {
            let unlocked = self.unlock_scan(&initial, password, known).await?;
            if pending_id.as_deref() == Some(&unlocked.0) {
                self.store.content_transaction(|s| {
                    s.remove(&self.pending_name);
                    Ok(())
                })?;
            }
            return Ok(unlocked);
        }
        ensure!(
            known.is_empty(),
            unavailable("known password metadata is missing; do not initialize a replacement")
        );
        ensure!(
            initial.entries.is_empty()
                || pending.is_some() && initial.entries.iter().all(|e| e.name.ends_with(".root")),
            unavailable("an incomplete password location exists; preserve initialization material")
        );
        let descriptor = if let Some(pending) = pending {
            pending
        } else {
            ensure!(self.client.writable(), unavailable("location is read-only"));
            let password = Zeroizing::new(password.to_owned());
            let descriptor = tokio::task::spawn_blocking(move || {
                let key = content_crypto::new_key()?;
                content_crypto::create_password_location(&super::new_uuid()?, &key, &password)
            })
            .await
            .map_err(|_| PlatformFailure)??;
            self.store.content_transaction(|s| {
                s.insert(
                    self.pending_name.clone(),
                    Zeroizing::new(STANDARD.encode(&descriptor)),
                );
                Ok(())
            })?;
            descriptor
        };
        let unlocked = unlock_envelope(&descriptor, password).await?;
        let (id, key) = &unlocked;
        initial.unique(Some(id))?;
        ensure!(self.client.writable(), unavailable("location is read-only"));
        let directory = match initial.directory {
            Some(path) => path,
            None => self.create_directory().await?,
        };
        self.scan().await?.unique(Some(id))?;
        let root: Commit = serde_json::from_value(serde_json::json!({
            "vaultId":id,"operationId":id,"entryId":id,"parentId":"","name":"","kind":"Root",
            "ciphertextDigest":digest(&descriptor)
        }))?;
        self.write_immutable(
            &directory,
            &(id.to_owned() + ".root"),
            &content_history::encode(&root, key)?,
            id,
        )
        .await?;
        self.scan().await?.unique(Some(id))?;
        self.write_immutable(&directory, &(id.to_owned() + ".location"), &descriptor, id)
            .await?;
        let published = self.scan().await?;
        published.unique(Some(id))?;
        ensure!(
            published.candidates().len() == 1,
            unavailable("password location publication is not visible")
        );
        self.verify_root(&published, &descriptor, id, key, &mut BTreeMap::new())
            .await?;
        self.store.content_transaction(|s| {
            s.remove(&self.pending_name);
            Ok(())
        })?;
        Ok(unlocked)
    }
    pub async fn unlock(
        &self,
        password: &str,
        known: &str,
    ) -> Result<(String, Zeroizing<[u8; 32]>)> {
        self.unlock_scan(&self.scan().await?, password, known).await
    }
    async fn unlock_scan(
        &self,
        scan: &Scan,
        password: &str,
        known: &str,
    ) -> Result<(String, Zeroizing<[u8; 32]>)> {
        scan.unique(None)?;
        let candidates = scan.candidates();
        ensure!(
            candidates.len() == 1,
            unavailable("password descriptor is missing")
        );
        let descriptor = self.bytes(scan, candidates[0], 124).await?;
        let id = content_crypto::password_location_id(&descriptor)?;
        ensure!(
            candidates[0].name == id.clone() + ".location" && (known.is_empty() || known == id),
            unavailable("password location identity changed")
        );
        let unlocked = unlock_envelope(&descriptor, password).await?;
        self.verify_root(scan, &descriptor, &id, &unlocked.1, &mut BTreeMap::new())
            .await?;
        let verified = self.scan().await?;
        verified.unique(Some(&id))?;
        ensure!(
            verified.candidates().len() == 1,
            unavailable("password metadata disappeared during unlock")
        );
        Ok(unlocked)
    }
    async fn verify_root(
        &self,
        scan: &Scan,
        descriptor: &[u8],
        id: &str,
        key: &[u8; 32],
        batch: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let roots = scan.roots();
        let root = roots
            .iter()
            .find(|e| e.name == id.to_owned() + ".root")
            .ok_or_else(|| {
                unavailable("password root is missing; do not initialize a replacement")
            })?;
        let bytes = self
            .metadata_bytes(scan, root, METADATA_LIMIT, batch)
            .await?;
        let record = content_history::decode(&bytes, key, id)?;
        ensure!(
            record.kind == Kind::Root
                && record.operation_id == id
                && record.ciphertext_digest == digest(descriptor),
            unavailable("password root does not authenticate its descriptor")
        );
        Ok(bytes)
    }
    pub async fn authenticate_location(&self, id: &str, key: &[u8; 32]) -> Result<()> {
        self.authenticated_root(&self.scan().await?, id, key, &mut BTreeMap::new())
            .await?;
        Ok(())
    }
    async fn authenticated_root(
        &self,
        scan: &Scan,
        id: &str,
        key: &[u8; 32],
        batch: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        scan.unique(Some(id))?;
        let candidates = scan.candidates();
        ensure!(
            candidates.len() == 1,
            unavailable("known password descriptor missing")
        );
        let descriptor = self.metadata_bytes(scan, candidates[0], 124, batch).await?;
        ensure!(
            content_crypto::password_location_id(&descriptor)? == id,
            unavailable("password identity changed")
        );
        self.verify_root(scan, &descriptor, id, key, batch).await
    }
    fn observed(&self, name: &str, digests: &BTreeMap<String, String>) -> Result<()> {
        if let Some(bytes) = self.store.content_setting(name) {
            verify_checkpoint(&bytes, digests)?;
        }
        Ok(())
    }
    pub async fn history(
        &self,
        id: &str,
        key: &[u8; 32],
        verify_contents: bool,
    ) -> Result<History> {
        let current = self.scan().await?;
        current.unique(Some(id))?;
        let mut entries = current.candidates();
        ensure!(
            entries.len() == 1,
            unavailable("known password descriptor missing")
        );
        entries.extend(current.roots());
        let root_entries = entries.len();
        entries.extend(
            current
                .entries
                .iter()
                .filter(|e| e.name.ends_with(".commit")),
        );
        ensure!(
            entries.len() - root_entries < MAX_RECORDS,
            unavailable("content history exceeds replay limit")
        );
        let mut batches = entries.chunks(METADATA_BATCH_SIZE);
        let first = batches.next().context("password metadata missing")?;
        let mut batch = self.metadata_batch(&current, first).await?;
        let root = self
            .authenticated_root(&current, id, key, &mut batch)
            .await?;
        let mut records = vec![content_history::decode(&root, key, id)?];
        let mut digests = BTreeMap::from([(id.to_owned(), digest(&root))]);
        for (index, entries) in std::iter::once(first).chain(batches).enumerate() {
            if index != 0 {
                batch = self.metadata_batch(&current, entries).await?;
            }
            for entry in entries.iter().filter(|e| e.name.ends_with(".commit")) {
                let bytes = self
                    .metadata_bytes(&current, entry, METADATA_LIMIT, &mut batch)
                    .await?;
                let record = content_history::decode(&bytes, key, id)?;
                ensure!(
                    entry.name == record.operation_id.clone() + ".commit"
                        && record.kind != Kind::Root,
                    unavailable("content commit name or root identity changed")
                );
                digests.insert(record.operation_id.clone(), digest(&bytes));
                records.push(record);
            }
        }
        let checkpoint =
            "auth.storage.password-location.checkpoint.".to_owned() + &digest(id.as_bytes());
        self.observed(&checkpoint, &digests)?;
        let history = History::replay(id, records).map_err(|e| {
            if e.is::<ContentError>() {
                e
            } else {
                unavailable("invalid authenticated content history")
            }
        })?;
        for record in history
            .heads()
            .values()
            .flatten()
            .map(|op| &history.records()[op])
            .filter(|r| r.kind == Kind::File)
        {
            require_object(&current, record)?;
            if verify_contents {
                self.verify_object_scan(&current, record).await?;
            }
        }
        self.store.content_transaction(|settings| {
            if let Some(previous) = settings.get(&checkpoint) {
                verify_checkpoint(previous, &digests)?;
            }
            settings.insert(
                checkpoint,
                Zeroizing::new(serde_json::to_string(&Checkpoint {
                    version: 1,
                    records: digests,
                })?),
            );
            Ok(())
        })?;
        Ok(history)
    }
    pub async fn object_path(&self, object_id: &str) -> Result<Path> {
        content_crypto::canonical_uuid(object_id)?;
        let scan = self.scan().await?;
        super::child_path(
            scan.directory
                .as_ref()
                .ok_or_else(|| unavailable("password directory missing"))?,
            &(object_id.to_owned() + ".object"),
        )
    }
    async fn verify_object_scan(&self, scan: &Scan, record: &Commit) -> Result<()> {
        ensure!(
            self.matches(
                scan,
                &record.object_id,
                record.ciphertext_length,
                &record.ciphertext_digest
            )
            .await?,
            unavailable("committed ciphertext object is missing, damaged or changed")
        );
        Ok(())
    }
    pub async fn verify_object(&self, record: &Commit) -> Result<()> {
        record.validate()?;
        ensure!(
            record.kind == Kind::File,
            "only file records have ciphertext objects"
        );
        let scan = self.scan().await?;
        scan.unique(Some(&record.vault_id))?;
        self.verify_object_scan(&scan, record).await
    }
    pub async fn object_matches(&self, object_id: &str, length: i64, digest: &str) -> Result<bool> {
        self.matches(&self.scan().await?, object_id, length, digest)
            .await
    }
    async fn matches(
        &self,
        scan: &Scan,
        object_id: &str,
        length: i64,
        expected: &str,
    ) -> Result<bool> {
        let Some(entry) = scan
            .entries
            .iter()
            .find(|e| e.name == object_id.to_owned() + ".object")
        else {
            return Ok(false);
        };
        if entry.size != length {
            return Ok(false);
        }
        let path = child(
            scan.directory
                .as_ref()
                .ok_or_else(|| unavailable("password directory missing"))?,
            entry,
        );
        let (sender, mut receiver) = mpsc::channel::<DownloadPart>(2);
        let producer = async {
            let result = self
                .client
                .download(
                    &path.path,
                    length,
                    &sender,
                    self.cancel,
                    path.reference.as_ref(),
                )
                .await;
            drop(sender);
            result
        };
        let consumer = async {
            let mut hash = Sha256::new();
            let mut size = 0i64;
            while let Some(part) = receiver.recv().await {
                let (bytes, _) = part?;
                ensure!(
                    bytes.len() as u64 <= (length - size) as u64,
                    unavailable("ciphertext object length changed")
                );
                hash.update(&bytes);
                size += bytes.len() as i64;
            }
            Ok::<_, anyhow::Error>(size == length && hex::encode(hash.finalize()) == expected)
        };
        let (_, matched) = tokio::try_join!(producer, consumer)?;
        Ok(matched)
    }
    pub async fn publish(&self, record: &Commit, key: &[u8; 32]) -> Result<()> {
        record.validate()?;
        ensure!(
            record.kind != Kind::Root,
            "a root cannot be republished as a file operation"
        );
        ensure!(self.client.writable(), unavailable("location is read-only"));
        let before = self.history(&record.vault_id, key, false).await?;
        if let Some(previous) = before.records().get(&record.operation_id) {
            ensure!(
                previous == record,
                unavailable("content operation identity reused with different data")
            );
            before.head(&record.entry_id)?;
            if record.kind == Kind::File {
                self.verify_object(record).await?;
            }
            return Ok(());
        }
        let mut records: Vec<_> = before.records().values().cloned().collect();
        records.push(record.clone());
        History::replay(&record.vault_id, records)
            .map_err(|_| unavailable("invalid content publication history"))?;
        for parent in &record.parents {
            ensure!(
                before
                    .records()
                    .get(parent)
                    .is_some_and(|r| r.entry_id == record.entry_id),
                unavailable("content parent revision missing or belongs to another entry")
            );
        }
        if record.kind != Kind::Delete {
            let parent = before
                .head(&record.parent_id)?
                .ok_or_else(|| unavailable("target directory missing"))?;
            ensure!(
                matches!(parent.kind, Kind::Directory | Kind::Root),
                unavailable("target is not a live directory")
            );
        }
        let current = self.scan().await?;
        if record.kind == Kind::File {
            require_object(&current, record)?;
            self.verify_object_scan(&current, record).await?;
        }
        let directory = current
            .directory
            .ok_or_else(|| unavailable("password directory missing"))?;
        self.write_immutable(
            &directory,
            &(record.operation_id.clone() + ".commit"),
            &content_history::encode(record, key)?,
            &record.vault_id,
        )
        .await?;
        let confirmed = self.history(&record.vault_id, key, false).await?;
        ensure!(
            confirmed.records().get(&record.operation_id) == Some(record),
            unavailable("publication could not be confirmed")
        );
        if record.kind == Kind::File {
            self.verify_object(record).await?;
        }
        if let Some(head) = confirmed.head(&record.entry_id)? {
            if head.kind != Kind::Delete {
                confirmed
                    .path(head)
                    .map_err(|_| unavailable("invalid published content hierarchy"))?;
            }
        }
        if record.kind != Kind::Delete {
            ensure!(
                !confirmed
                    .heads()
                    .values()
                    .flatten()
                    .map(|op| &confirmed.records()[op])
                    .any(|r| r.entry_id != record.entry_id
                        && r.kind != Kind::Delete
                        && r.parent_id == record.parent_id
                        && r.name == record.name),
                unavailable("concurrent entries have the same logical name; preserve both")
            );
        }
        Ok(())
    }
}
fn require_object<'a>(scan: &'a Scan, record: &Commit) -> Result<&'a Entry> {
    scan.entries
        .iter()
        .find(|e| {
            e.name == record.object_id.clone() + ".object" && e.size == record.ciphertext_length
        })
        .ok_or_else(|| unavailable("committed object missing or changed length"))
}
fn verify_checkpoint(bytes: &str, current: &BTreeMap<String, String>) -> Result<()> {
    let previous: Checkpoint = serde_json::from_str(bytes)?;
    ensure!(
        previous.version == 1 && previous.records.len() <= MAX_RECORDS,
        unavailable("unsupported content checkpoint")
    );
    ensure!(
        previous
            .records
            .iter()
            .all(|(id, hash)| current.get(id) == Some(hash)),
        unavailable("content history is incomplete or older than previously observed")
    );
    Ok(())
}
fn internal_name(name: &str) -> bool {
    let Some((id, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    id.len() == 36
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
        && matches!(suffix, "location" | "root" | "commit" | "object")
}
fn child(parent: &Path, entry: &Entry) -> Path {
    Path {
        path: parent.path.trim_end_matches('/').to_owned() + "/" + &entry.name,
        reference: entry.reference.clone(),
    }
}
async fn read_bytes(
    client: &Client,
    path: &Path,
    size: i64,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let (sender, mut receiver) = mpsc::channel::<DownloadPart>(2);
    let producer = async {
        let result = client
            .download(&path.path, size, &sender, cancel, path.reference.as_ref())
            .await;
        drop(sender);
        result
    };
    let consumer = async {
        let mut data = Vec::new();
        while let Some(part) = receiver.recv().await {
            let (bytes, _) = part?;
            ensure!(
                bytes.len() <= limit - data.len(),
                unavailable("password metadata exceeds bounded format")
            );
            data.extend_from_slice(&bytes);
        }
        Ok::<_, anyhow::Error>(data)
    };
    let (_, bytes) = tokio::try_join!(producer, consumer)?;
    Ok(bytes)
}
async fn upload_bytes(
    client: &Client,
    path: &Path,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<()> {
    let (sender, receiver) = mpsc::channel(2);
    let producer = async {
        for chunk in bytes.chunks(64 * 1024) {
            sender
                .send(chunk.to_vec())
                .await
                .map_err(|_| PlatformFailure)?;
        }
        drop(sender);
        Ok::<_, anyhow::Error>(())
    };
    let consumer = client.upload(
        &path.path,
        bytes.len() as i64,
        receiver,
        Arc::new(AtomicU64::new(0)),
        cancel,
        path.reference.as_ref(),
    );
    let (_, written) = tokio::try_join!(producer, consumer)?;
    ensure!(written, unavailable("password metadata upload failed"));
    Ok(())
}

async fn unlock_envelope(bytes: &[u8], password: &str) -> Result<(String, Zeroizing<[u8; 32]>)> {
    let bytes = bytes.to_vec();
    let password = Zeroizing::new(password.to_owned());
    tokio::task::spawn_blocking(move || content_crypto::unlock_password_location(&bytes, &password))
        .await
        .map_err(|_| PlatformFailure)?
}
