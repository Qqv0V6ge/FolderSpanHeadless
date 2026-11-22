use super::vault::{NAMESPACE, Vault};
use super::{Client, FileInfo, Location, Path, child_path, for_path, new_uuid};
use crate::{
    management::reply::PlatformFailure,
    storage::{
        content_crypto::{ContentError, ErrorCode},
        content_history::{Commit, DirectoryBinding, History, Kind, MAX_RECORDS},
        remote::{Entry, reference_defaults},
    },
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn conflict(message: &'static str) -> anyhow::Error {
    ContentError(ErrorCode::Conflict, message).into()
}
fn changed(message: &'static str) -> anyhow::Error {
    ContentError(ErrorCode::SourceChanged, message).into()
}
fn uncertain(message: &'static str) -> anyhow::Error {
    ContentError(ErrorCode::UncertainResult, message).into()
}
fn canonical(path: &str) -> String {
    let value = path.replace('\\', "/");
    let value = value.trim_end_matches('/');
    if value.is_empty() {
        "/".into()
    } else {
        value.into()
    }
}
fn prefix(path: &str) -> String {
    path.trim_end_matches('/').to_owned() + "/"
}
fn join(parent: &str, child: &str) -> String {
    parent.trim_end_matches('/').to_owned() + "/" + child.trim_start_matches('/')
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(p, _)| p)
        .filter(|p| !p.is_empty())
        .unwrap_or("/")
}
fn name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|p| !p.is_empty())
        .unwrap_or("/")
}
fn ref_text<'a>(reference: Option<&'a Value>, field: &str) -> &'a str {
    reference
        .and_then(|r| r.get(field))
        .and_then(Value::as_str)
        .unwrap_or("")
}
fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.trim().is_empty()
            && !name.contains(['/', '\\'])
            && !name.chars().any(char::is_control)
            && !matches!(name, "." | ".."),
        conflict("an unsafe ordinary entry name was returned")
    );
    crate::storage::remote::validate_write_path(&("/".to_owned() + name))?;
    Ok(())
}
fn native_reference(reference: Option<&Value>) -> Option<Value> {
    let id = ref_text(reference, "id");
    if id.is_empty() {
        None
    } else {
        Some(reference_defaults(
            &json!({"id":id,"parentId":ref_text(reference,"parentId")}),
        ))
    }
}
struct View {
    history: History,
    live: Vec<Commit>,
    bindings: BTreeMap<String, Commit>,
    native: BTreeMap<String, Commit>,
}
#[derive(Clone)]
struct Node {
    path: String,
    record: Option<Commit>,
    raw: Option<Entry>,
    physical: Option<Path>,
    anchor: Option<Commit>,
    ordinary: String,
}
impl Node {
    fn directory(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(|r| matches!(r.kind, Kind::Root | Kind::Directory))
            || self.raw.as_ref().is_some_and(|r| r.is_directory)
    }
}
pub(super) struct PreparedFile<'a> {
    pub operation_id: &'a str,
    pub object_id: &'a str,
    pub ciphertext_length: i64,
    pub ciphertext_digest: &'a str,
    pub size: i64,
    pub updated_date: i64,
}
pub(super) struct Logical<'a> {
    client: &'a Client,
    reference: &'a Location,
    vault: &'a Vault<'a>,
    key: &'a [u8; 32],
    root: String,
}
impl<'a> Logical<'a> {
    pub fn new(
        client: &'a Client,
        reference: &'a Location,
        vault: &'a Vault<'a>,
        key: &'a [u8; 32],
    ) -> Self {
        Self {
            client,
            reference,
            vault,
            key,
            root: canonical(&reference.root.path),
        }
    }
    async fn view(&self) -> Result<View> {
        let history = self
            .vault
            .history(&self.reference.vault_id, self.key, false)
            .await?;
        let live = history
            .live_entries()
            .map_err(|e| {
                if e.is::<ContentError>() {
                    e
                } else {
                    conflict("the authenticated hierarchy has conflicting names or parents")
                }
            })?
            .into_iter()
            .cloned()
            .collect();
        let mut bindings = BTreeMap::new();
        let mut native = BTreeMap::new();
        for id in history.heads().keys() {
            let Some(record) = history.head(id)? else {
                continue;
            };
            let Some(binding) = &record.ordinary_directory else {
                continue;
            };
            let path = self.physical(binding)?.path;
            ensure!(
                bindings.insert(path, record.clone()).is_none(),
                conflict("ordinary directory has multiple authenticated owners")
            );
            let id = ref_text(binding.reference.as_ref(), "id");
            if !id.is_empty() {
                ensure!(
                    id != ref_text(self.reference.root.reference.as_ref(), "id")
                        && native.insert(id.to_owned(), record.clone()).is_none(),
                    conflict("native directory has multiple authenticated owners")
                );
            }
        }
        Ok(View {
            history,
            live,
            bindings,
            native,
        })
    }
    pub async fn list(&self, path: &Path) -> Result<Vec<Entry>> {
        let view = self.view().await?;
        let node = self.resolve(path, &view).await?.ok_or(PlatformFailure)?;
        ensure!(
            node.directory(),
            conflict("selected entry is not a directory")
        );
        let mut entries = self
            .children(&node, &view)
            .await?
            .iter()
            .map(|n| self.entry(n))
            .collect::<Result<Vec<_>>>()?;
        entries.sort_by(|a, b| a.name.encode_utf16().cmp(b.name.encode_utf16()));
        Ok(entries)
    }
    pub async fn stat(&self, path: &Path) -> Result<Option<Entry>> {
        let view = self.view().await?;
        self.resolve(path, &view)
            .await?
            .map(|n| self.entry(&n))
            .transpose()
    }
    pub async fn resolve_download(&self, file: &FileInfo) -> Result<(FileInfo, Path, i64)> {
        let view = self.view().await?;
        let node = self
            .resolve(
                &Path {
                    path: file.path.clone(),
                    reference: file.storage_reference.clone(),
                },
                &view,
            )
            .await?
            .ok_or(PlatformFailure)?;
        ensure!(
            !node.directory() && !node.raw.as_ref().is_some_and(|r| r.is_symbolic_link),
            conflict("selected entry is not an ordinary file")
        );
        let metadata = self.entry(&node)?;
        if node.raw.is_some() {
            ensure!(
                file.size == metadata.size
                    && !(file.updated_date > 0
                        && metadata.updated_date > 0
                        && file.updated_date != metadata.updated_date)
                    && !(file.created_date > 0
                        && metadata.created_date > 0
                        && file.created_date != metadata.created_date),
                changed("ordinary source metadata changed")
            );
        }
        let mut logical = file.clone();
        logical.name = metadata.name;
        logical.path = metadata.path;
        logical.size = metadata.size;
        logical.updated_date = metadata.updated_date;
        logical.storage_reference = metadata.reference;
        if let Some(record) = node.record {
            Ok((
                logical,
                self.vault.object_path(&record.object_id).await?,
                record.ciphertext_length,
            ))
        } else {
            Ok((
                logical,
                node.physical.ok_or(PlatformFailure)?,
                metadata.size,
            ))
        }
    }
    pub async fn prepare_file(&self, target: &Path, object: PreparedFile<'_>) -> Result<Commit> {
        let PreparedFile {
            operation_id,
            object_id,
            ciphertext_length: cipher_length,
            ciphertext_digest: digest,
            size: plain_size,
            updated_date,
        } = object;
        let view = self.view().await?;
        let path = self.logical_path(target, &view)?;
        let selected = Path {
            path: path.clone(),
            reference: None,
        };
        let existing = self.resolve(&selected, &view).await?;
        ensure!(
            !existing
                .as_ref()
                .is_some_and(|n| n.raw.is_some() || n.directory()),
            conflict("ordinary file or directory already occupies encrypted target")
        );
        if let Some(record) = existing.as_ref().and_then(|n| n.record.as_ref()) {
            self.vault.verify_object(record).await?;
        }
        let parent_record = self
            .authenticated_directory(parent(&path), Some(&view))
            .await?;
        let view = self.view().await?;
        ensure!(
            self.logical_path(target, &view)? == path
                && self
                    .resolve(
                        &Path {
                            path: parent(&path).into(),
                            reference: None
                        },
                        &view
                    )
                    .await?
                    .and_then(|n| n.record)
                    .is_some_and(|r| r.entry_id == parent_record.entry_id),
            changed("upload parent changed during preparation")
        );
        let current = self.resolve(&selected, &view).await?;
        ensure!(
            !current
                .as_ref()
                .is_some_and(|n| n.raw.is_some() || n.directory()),
            conflict("encrypted target changed")
        );
        ensure!(
            current.as_ref().and_then(|n| n.record.as_ref())
                == existing.as_ref().and_then(|n| n.record.as_ref()),
            changed("upload target changed during preparation")
        );
        let previous = current.and_then(|n| n.record);
        let record = Commit {
            version: 1,
            vault_id: self.reference.vault_id.clone(),
            operation_id: operation_id.into(),
            entry_id: previous
                .as_ref()
                .map(|r| r.entry_id.clone())
                .unwrap_or(new_uuid()?),
            parent_id: parent_record.entry_id,
            name: name(&path).into(),
            parents: previous.map(|r| vec![r.operation_id]).unwrap_or_default(),
            kind: Kind::File,
            object_id: object_id.into(),
            ciphertext_length: cipher_length,
            ciphertext_digest: digest.into(),
            size: plain_size,
            updated_date,
            ordinary_directory: None,
        };
        record.validate()?;
        Ok(record)
    }
    pub async fn ordinary_upload(&self, target: &Path) -> Result<Path> {
        let view = self.view().await?;
        let path = self.logical_path(target, &view)?;
        let existing = self
            .resolve(
                &Path {
                    path: path.clone(),
                    reference: None,
                },
                &view,
            )
            .await?;
        ensure!(
            !existing
                .as_ref()
                .is_some_and(|n| n.record.is_some() || n.directory()),
            conflict("authenticated entry occupies ordinary target")
        );
        let directory = self
            .resolve(
                &Path {
                    path: parent(&path).into(),
                    reference: None,
                },
                &view,
            )
            .await?
            .ok_or(PlatformFailure)?;
        ensure!(
            directory.directory(),
            conflict("upload parent is not a directory")
        );
        let backing = self
            .backing(&directory, true)
            .await?
            .ok_or(PlatformFailure)?;
        self.child(&backing, name(&path))
    }
    pub async fn mkdir(&self, path: &Path, encrypted: bool) -> Result<bool> {
        let view = self.view().await?;
        let logical = self.logical_path(path, &view)?;
        ensure!(
            self.resolve(
                &Path {
                    path: logical.clone(),
                    reference: None
                },
                &view
            )
            .await?
            .is_none(),
            conflict("directory target exists")
        );
        if encrypted {
            let parent = self.authenticated_directory(parent(&logical), None).await?;
            let record = Commit {
                version: 1,
                vault_id: self.reference.vault_id.clone(),
                operation_id: new_uuid()?,
                entry_id: new_uuid()?,
                parent_id: parent.entry_id,
                name: name(&logical).into(),
                parents: Vec::new(),
                kind: Kind::Directory,
                object_id: String::new(),
                ciphertext_length: 0,
                ciphertext_digest: String::new(),
                size: 0,
                updated_date: crate::storage::accounts::now(),
                ordinary_directory: None,
            };
            self.vault.publish(&record, self.key).await?;
        } else {
            let parent = self
                .resolve(
                    &Path {
                        path: parent(&logical).into(),
                        reference: None,
                    },
                    &view,
                )
                .await?
                .ok_or(PlatformFailure)?;
            ensure!(
                parent.directory(),
                conflict("directory parent is not a directory")
            );
            let physical = self.child(
                &self.backing(&parent, true).await?.ok_or(PlatformFailure)?,
                name(&logical),
            )?;
            ensure!(
                self.client
                    .mutate(
                        "/mkdir",
                        &physical.path,
                        "",
                        true,
                        physical.reference.as_ref(),
                        None
                    )
                    .await?,
                uncertain("ordinary directory creation was not confirmed")
            );
        }
        Ok(true)
    }
    pub async fn rename(&self, source: &Path, target: &Path) -> Result<bool> {
        let mut view = self.view().await?;
        let mut selected = self.resolve(source, &view).await?.ok_or(PlatformFailure)?;
        let destination = self.logical_path(target, &view)?;
        if selected.path == destination {
            return Ok(true);
        }
        ensure!(
            selected.path != self.root
                && !(selected.directory() && destination.starts_with(&prefix(&selected.path))),
            conflict("directory cannot move into itself or replace location root")
        );
        ensure!(
            self.resolve(
                &Path {
                    path: destination.clone(),
                    reference: None
                },
                &view
            )
            .await?
            .is_none(),
            conflict("rename target exists")
        );
        self.verify_managed(&selected, &view).await?;
        if selected.directory() && selected.record.is_none() {
            self.authenticated_directory(&selected.path, None).await?;
            view = self.view().await?;
            selected = self
                .resolve(
                    &Path {
                        path: selected.path.clone(),
                        reference: None,
                    },
                    &view,
                )
                .await?
                .ok_or(PlatformFailure)?;
        }
        if let Some(record) = &selected.record {
            let parent = self
                .authenticated_directory(parent(&destination), None)
                .await?;
            let current = self.view().await?;
            ensure!(
                current.history.head(&record.entry_id)? == Some(record),
                changed("rename source changed")
            );
            if selected.directory() {
                self.verify_managed(&self.managed(record, &current)?, &current)
                    .await?;
            }
            let updated = Commit {
                operation_id: new_uuid()?,
                parent_id: parent.entry_id,
                name: name(&destination).into(),
                parents: vec![record.operation_id.clone()],
                updated_date: crate::storage::accounts::now(),
                ..record.clone()
            };
            self.vault.publish(&updated, self.key).await?;
        } else {
            ensure!(
                !selected.raw.as_ref().is_some_and(|r| r.is_symbolic_link),
                conflict("symbolic links cannot move through a password location")
            );
            let raw = selected.physical.as_ref().ok_or(PlatformFailure)?;
            let target = self
                .ordinary_upload(&Path {
                    path: destination,
                    reference: None,
                })
                .await?;
            ensure!(
                self.client
                    .mutate(
                        "/move",
                        &raw.path,
                        &target.path,
                        false,
                        raw.reference.as_ref(),
                        target.reference.as_ref()
                    )
                    .await?,
                uncertain("ordinary file rename was not confirmed")
            );
        }
        Ok(true)
    }
    pub async fn delete(&self, path: &Path, directory: bool) -> Result<bool> {
        let mut view = self.view().await?;
        let mut selected = self.resolve(path, &view).await?.ok_or(PlatformFailure)?;
        ensure!(
            selected.path != self.root && selected.directory() == directory,
            conflict("deletion target or type invalid")
        );
        let mut plan = BTreeMap::new();
        self.collect(&selected, &view, &mut plan).await?;
        if selected.directory() && selected.record.is_none() {
            self.authenticated_directory(&selected.path, None).await?;
            view = self.view().await?;
            selected = self
                .resolve(
                    &Path {
                        path: selected.path.clone(),
                        reference: None,
                    },
                    &view,
                )
                .await?
                .ok_or(PlatformFailure)?;
            plan.insert(selected.path.clone(), selected.clone());
        }
        self.remove(&selected, &plan).await?;
        Ok(true)
    }
    async fn collect(
        &self,
        node: &Node,
        view: &View,
        plan: &mut BTreeMap<String, Node>,
    ) -> Result<()> {
        let depth = if node.path == self.root {
            0
        } else {
            node.path
                .strip_prefix(&prefix(&self.root))
                .unwrap_or(&node.path)
                .split('/')
                .count()
        };
        ensure!(
            plan.len() < MAX_RECORDS
                && node.path.encode_utf16().count() <= 16 * 1024
                && depth <= 256,
            conflict("deletion subtree exceeds traversal limit")
        );
        ensure!(
            plan.insert(node.path.clone(), node.clone()).is_none()
                && !node.raw.as_ref().is_some_and(|r| r.is_symbolic_link),
            conflict("unsafe or repeated deletion entry")
        );
        if let Some(record) = node.record.as_ref().filter(|r| r.kind == Kind::File) {
            self.vault.verify_object(record).await?;
        }
        if node.directory() {
            for child in self.children(node, view).await? {
                Box::pin(self.collect(&child, view, plan)).await?;
            }
        }
        Ok(())
    }
    async fn remove(&self, expected: &Node, plan: &BTreeMap<String, Node>) -> Result<()> {
        let view = self.view().await?;
        let path = Path {
            path: expected.path.clone(),
            reference: None,
        };
        let node = self
            .resolve(&path, &view)
            .await?
            .ok_or_else(|| changed("deletion entry disappeared"))?;
        self.same_observed(expected, &node)?;
        if node.directory() {
            let visible = self.children(&node, &view).await?;
            let planned: Vec<_> = plan
                .values()
                .filter(|n| parent(&n.path) == node.path)
                .collect();
            ensure!(
                visible.iter().map(|n| &n.path).collect::<BTreeSet<_>>()
                    == planned.iter().map(|n| &n.path).collect(),
                changed("deletion subtree changed")
            );
            for child in planned {
                Box::pin(self.remove(child, plan)).await?;
            }
            let mut latest_view = self.view().await?;
            let mut latest = self
                .resolve(&path, &latest_view)
                .await?
                .ok_or_else(|| changed("deletion directory disappeared"))?;
            ensure!(
                self.children(&latest, &latest_view).await?.is_empty(),
                changed("new data appeared during deletion")
            );
            if latest.record.is_none() {
                let physical = latest.physical.as_ref().ok_or(PlatformFailure)?;
                let raw = self
                    .client
                    .list(&physical.path, physical.reference.as_ref())
                    .await?;
                if raw.is_empty() {
                    ensure!(
                        self.client.delete_empty(physical).await?,
                        uncertain("empty directory deletion was not confirmed")
                    );
                    return Ok(());
                }
                self.authenticated_directory(&latest.path, None).await?;
                latest_view = self.view().await?;
                latest = self
                    .resolve(&path, &latest_view)
                    .await?
                    .ok_or(PlatformFailure)?;
                ensure!(
                    self.children(&latest, &latest_view).await?.is_empty(),
                    changed("bound deletion directory changed")
                );
            }
            self.tombstone(latest.record.as_ref().ok_or(PlatformFailure)?)
                .await?;
        } else if let Some(record) = &node.record {
            self.tombstone(record).await?;
        } else {
            let physical = node.physical.as_ref().ok_or(PlatformFailure)?;
            ensure!(
                self.client
                    .mutate(
                        "/delete",
                        &physical.path,
                        "",
                        false,
                        physical.reference.as_ref(),
                        None
                    )
                    .await?,
                uncertain("ordinary file deletion was not confirmed")
            );
        }
        Ok(())
    }
    async fn verify_managed(&self, selected: &Node, view: &View) -> Result<()> {
        for record in &view.live {
            if record.kind != Kind::File {
                continue;
            }
            let path = self.managed(record, view)?.path;
            if path == selected.path
                || selected.directory() && path.starts_with(&prefix(&selected.path))
            {
                self.vault.verify_object(record).await?;
            }
        }
        Ok(())
    }
    async fn tombstone(&self, record: &Commit) -> Result<()> {
        if record.kind == Kind::File {
            self.vault.verify_object(record).await?;
        }
        ensure!(
            self.view().await?.history.head(&record.entry_id)? == Some(record),
            changed("authenticated entry changed before deletion")
        );
        let deleted = Commit {
            version: 1,
            vault_id: self.reference.vault_id.clone(),
            operation_id: new_uuid()?,
            entry_id: record.entry_id.clone(),
            parent_id: record.parent_id.clone(),
            name: record.name.clone(),
            parents: vec![record.operation_id.clone()],
            kind: Kind::Delete,
            object_id: String::new(),
            ciphertext_length: 0,
            ciphertext_digest: String::new(),
            size: 0,
            updated_date: crate::storage::accounts::now(),
            ordinary_directory: record.ordinary_directory.clone(),
        };
        self.vault.publish(&deleted, self.key).await
    }
    fn same_observed(&self, expected: &Node, actual: &Node) -> Result<()> {
        if expected.record.is_some() {
            ensure!(
                expected.record == actual.record,
                changed("authenticated deletion entry changed")
            );
        } else {
            let without_context = |raw: &Option<Entry>| {
                raw.as_ref().map(|r| Entry {
                    path: String::new(),
                    reference: None,
                    ..r.clone()
                })
            };
            ensure!(
                without_context(&expected.raw) == without_context(&actual.raw)
                    && expected
                        .raw
                        .as_ref()
                        .and_then(|r| r.reference.as_ref())
                        .and_then(|r| r.get("id"))
                        == actual
                            .raw
                            .as_ref()
                            .and_then(|r| r.reference.as_ref())
                            .and_then(|r| r.get("id")),
                changed("ordinary deletion entry changed")
            );
        }
        Ok(())
    }
    async fn authenticated_directory(&self, path: &str, observed: Option<&View>) -> Result<Commit> {
        let owned = if observed.is_none() {
            Some(self.view().await?)
        } else {
            None
        };
        let view = observed.or(owned.as_ref()).expect("directory view exists");
        let node = self
            .resolve(
                &Path {
                    path: path.into(),
                    reference: None,
                },
                view,
            )
            .await?
            .ok_or(PlatformFailure)?;
        ensure!(
            node.directory() && !node.raw.as_ref().is_some_and(|r| r.is_symbolic_link),
            conflict("parent is not a safe directory")
        );
        if let Some(record) = &node.record {
            return Ok(record.clone());
        }
        let parent = Box::pin(self.authenticated_directory(parent(path), None)).await?;
        let view = self.view().await?;
        let latest = self
            .resolve(
                &Path {
                    path: path.into(),
                    reference: None,
                },
                &view,
            )
            .await?
            .ok_or_else(|| changed("parent directory disappeared"))?;
        if let Some(record) = &latest.record {
            return Ok(record.clone());
        }
        self.same_observed(&node, &latest)?;
        let raw = latest.physical.as_ref().ok_or(PlatformFailure)?;
        let native = native_reference(raw.reference.as_ref());
        let record = Commit {
            version: 1,
            vault_id: self.reference.vault_id.clone(),
            operation_id: new_uuid()?,
            entry_id: new_uuid()?,
            parent_id: parent.entry_id,
            name: name(path).into(),
            parents: Vec::new(),
            kind: Kind::Directory,
            object_id: String::new(),
            ciphertext_length: 0,
            ciphertext_digest: String::new(),
            size: 0,
            updated_date: latest.raw.as_ref().map(|r| r.updated_date).unwrap_or(0),
            ordinary_directory: Some(DirectoryBinding {
                relative_path: self.relative_physical(&raw.path)?,
                reference: native.clone(),
            }),
        };
        self.available_binding(
            &self.view().await?,
            &raw.path,
            ref_text(native.as_ref(), "id"),
            &record.entry_id,
        )?;
        self.vault.publish(&record, self.key).await?;
        self.view()
            .await?
            .history
            .head(&record.entry_id)?
            .cloned()
            .ok_or(PlatformFailure.into())
    }
    async fn backing(&self, node: &Node, materialize: bool) -> Result<Option<Path>> {
        if let Some(physical) = &node.physical {
            return Ok(Some(physical.clone()));
        }
        let record = node.record.as_ref().ok_or(PlatformFailure)?;
        if record.kind == Kind::Root {
            return Ok(Some(self.reference.root.clone()));
        }
        if let Some(binding) = &record.ordinary_directory {
            return Ok(Some(self.physical(binding)?));
        }
        if !materialize {
            return Ok(None);
        }
        let view = self.view().await?;
        let parent = view
            .history
            .head(&record.parent_id)?
            .ok_or_else(|| changed("backing parent disappeared"))?;
        let parent = self.managed(parent, &view)?;
        let physical = Box::pin(self.backing(&parent, true))
            .await?
            .ok_or(PlatformFailure)?;
        let target = self.child(&physical, &record.name)?;
        let entries = self
            .client
            .list(&physical.path, physical.reference.as_ref())
            .await?;
        ensure!(
            !entries.iter().any(|e| e.name == record.name)
                && !view.bindings.contains_key(&target.path),
            conflict("virtual directory backing target occupied")
        );
        ensure!(
            self.client
                .mutate(
                    "/mkdir",
                    &target.path,
                    "",
                    true,
                    target.reference.as_ref(),
                    None
                )
                .await?,
            uncertain("backing directory creation not confirmed")
        );
        let created = self.client.stat(&target).await?;
        ensure!(
            created.is_directory && !created.is_symbolic_link,
            conflict("directory backing changed")
        );
        let native = native_reference(created.reference.as_ref());
        let created_path = Path {
            path: target.path.clone(),
            reference: created.reference.clone().or(target.reference.clone()),
        };
        ensure!(
            self.client
                .list(&created_path.path, created_path.reference.as_ref())
                .await?
                .is_empty(),
            conflict("backing directory contains unobserved ordinary data")
        );
        let view = self.view().await?;
        ensure!(
            view.history.head(&record.entry_id)? == Some(record),
            changed("virtual directory changed during backing creation")
        );
        self.available_binding(
            &view,
            &target.path,
            ref_text(native.as_ref(), "id"),
            &record.entry_id,
        )?;
        let bound = Commit {
            operation_id: new_uuid()?,
            parents: vec![record.operation_id.clone()],
            ordinary_directory: Some(DirectoryBinding {
                relative_path: self.relative_physical(&target.path)?,
                reference: native,
            }),
            ..record.clone()
        };
        self.vault.publish(&bound, self.key).await?;
        Ok(Some(
            self.physical(bound.ordinary_directory.as_ref().unwrap())?,
        ))
    }
    async fn resolve(&self, path: &Path, view: &View) -> Result<Option<Node>> {
        let logical = self.logical_path(path, view)?;
        let base = view
            .history
            .head(&self.reference.vault_id)?
            .ok_or_else(|| conflict("authenticated root missing"))?;
        let mut node = self.managed(base, view)?;
        if logical == self.root {
            return self.verify_native(path, node).map(Some);
        }
        for part in logical
            .strip_prefix(&prefix(&self.root))
            .unwrap_or(&logical)
            .split('/')
        {
            if !node.directory() {
                return Ok(None);
            }
            let mut matches = self
                .children(&node, view)
                .await?
                .into_iter()
                .filter(|n| name(&n.path) == part);
            let Some(next) = matches.next() else {
                return Ok(None);
            };
            if matches.next().is_some() {
                return Ok(None);
            }
            node = next;
        }
        self.verify_native(path, node).map(Some)
    }
    fn verify_native(&self, path: &Path, node: Node) -> Result<Node> {
        let expected = ref_text(path.reference.as_ref(), "id");
        if !expected.is_empty()
            && !expected.starts_with("fsp-content:")
            && !expected.starts_with("fsp-ordinary:")
        {
            let actual = if let Some(raw) = &node.raw {
                ref_text(raw.reference.as_ref(), "id")
            } else {
                match node.record.as_ref().map(|r| r.kind) {
                    Some(Kind::Root) => ref_text(self.reference.root.reference.as_ref(), "id"),
                    Some(Kind::Directory) => node
                        .record
                        .as_ref()
                        .and_then(|r| r.ordinary_directory.as_ref())
                        .map(|b| ref_text(b.reference.as_ref(), "id"))
                        .unwrap_or(""),
                    _ => "",
                }
            };
            ensure!(
                expected == actual,
                changed("ordinary source identity changed")
            );
        }
        Ok(node)
    }
    async fn children(&self, directory: &Node, view: &View) -> Result<Vec<Node>> {
        ensure!(
            !directory.raw.as_ref().is_some_and(|r| r.is_symbolic_link),
            conflict("symbolic directory traversal unsupported")
        );
        let mut nodes = BTreeMap::new();
        if let Some(backing) = self.backing(directory, false).await? {
            let entries = self
                .client
                .list(&backing.path, backing.reference.as_ref())
                .await?;
            ensure!(
                entries
                    .iter()
                    .map(|e| &e.name)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == entries.len(),
                conflict("ordinary listing ambiguous")
            );
            for raw in entries {
                validate_name(&raw.name)?;
                if raw.name == NAMESPACE {
                    ensure!(
                        canonical(&backing.path) == self.root
                            && raw.is_directory
                            && !raw.is_symbolic_link,
                        conflict("unknown or replaced password namespace exists")
                    );
                    continue;
                }
                ensure!(
                    raw.name != ".folderspan-content.json",
                    conflict("unsupported content namespace exists")
                );
                let mut reference = raw.reference.clone();
                if let Some(r) = &mut reference {
                    r["content"] = Value::Null;
                }
                let physical = Path {
                    path: join(&backing.path, &raw.name),
                    reference,
                };
                if let Some(owner) = self.binding_owner(view, &physical.path, &raw)? {
                    ensure!(
                        raw.is_directory && !raw.is_symbolic_link,
                        conflict("authenticated directory backing replaced")
                    );
                    self.binding_identity(owner, &raw)?;
                    if owner.kind == Kind::Delete {
                        self.deleted_backing_empty(&physical, view, &mut BTreeSet::new(), 0)
                            .await?;
                    }
                    continue;
                }
                let anchor = directory
                    .record
                    .as_ref()
                    .or(directory.anchor.as_ref())
                    .ok_or(PlatformFailure)?
                    .clone();
                let ordinary = [directory.ordinary.as_str(), raw.name.as_str()]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("/");
                nodes.insert(
                    raw.name.clone(),
                    Node {
                        path: join(&directory.path, &raw.name),
                        record: None,
                        raw: Some(raw),
                        physical: Some(physical),
                        anchor: Some(anchor),
                        ordinary,
                    },
                );
            }
        }
        if let Some(parent) = &directory.record {
            for record in view.live.iter().filter(|r| r.parent_id == parent.entry_id) {
                ensure!(
                    nodes
                        .insert(record.name.clone(), self.managed(record, view)?)
                        .is_none(),
                    conflict("ordinary and authenticated entries share a logical name")
                );
            }
        }
        Ok(nodes.into_values().collect())
    }
    async fn deleted_backing_empty(
        &self,
        path: &Path,
        view: &View,
        visited: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<()> {
        ensure!(
            depth <= 256 && visited.insert(path.path.clone()) && visited.len() <= MAX_RECORDS,
            conflict("repeated deleted backing directory")
        );
        let entries = self
            .client
            .list(&path.path, path.reference.as_ref())
            .await?;
        ensure!(
            entries
                .iter()
                .map(|e| &e.name)
                .collect::<BTreeSet<_>>()
                .len()
                == entries.len(),
            conflict("ordinary listing ambiguous")
        );
        for entry in entries {
            validate_name(&entry.name)?;
            let mut reference = entry.reference.clone();
            if let Some(r) = &mut reference {
                r["content"] = Value::Null;
            }
            let raw = Path {
                path: join(&path.path, &entry.name),
                reference,
            };
            let owner = self.binding_owner(view, &raw.path, &entry)?;
            ensure!(
                owner.is_some() && entry.is_directory && !entry.is_symbolic_link,
                conflict("new ordinary data appeared in deleted authenticated directory")
            );
            let owner = owner.unwrap();
            self.binding_identity(owner, &entry)?;
            if owner.kind == Kind::Delete {
                Box::pin(self.deleted_backing_empty(&raw, view, visited, depth + 1)).await?;
            }
        }
        Ok(())
    }
    fn binding_owner<'b>(
        &self,
        view: &'b View,
        path: &str,
        raw: &Entry,
    ) -> Result<Option<&'b Commit>> {
        let id = ref_text(raw.reference.as_ref(), "id");
        ensure!(
            id.is_empty() || id != ref_text(self.reference.root.reference.as_ref(), "id"),
            conflict("ordinary child aliases location root")
        );
        Ok(view.bindings.get(path).or_else(|| {
            if id.is_empty() {
                None
            } else {
                view.native.get(id)
            }
        }))
    }
    fn available_binding(&self, view: &View, path: &str, native: &str, entry: &str) -> Result<()> {
        ensure!(
            ![
                view.bindings.get(path),
                if native.is_empty() {
                    None
                } else {
                    view.native.get(native)
                }
            ]
            .into_iter()
            .flatten()
            .any(|r| r.entry_id != entry)
                && (native.is_empty()
                    || native != ref_text(self.reference.root.reference.as_ref(), "id")),
            conflict("ordinary directory already bound to another authenticated entry")
        );
        Ok(())
    }
    fn binding_identity(&self, owner: &Commit, raw: &Entry) -> Result<()> {
        let expected = owner
            .ordinary_directory
            .as_ref()
            .map(|b| ref_text(b.reference.as_ref(), "id"))
            .unwrap_or("");
        ensure!(
            expected.is_empty() || expected == ref_text(raw.reference.as_ref(), "id"),
            conflict("authenticated directory backing identity replaced")
        );
        Ok(())
    }
    fn managed(&self, record: &Commit, view: &View) -> Result<Node> {
        let path = if record.kind == Kind::Root {
            self.root.clone()
        } else {
            join(
                &self.root,
                view.history.path(record)?.trim_start_matches('/'),
            )
        };
        Ok(Node {
            path,
            record: Some(record.clone()),
            raw: None,
            physical: None,
            anchor: None,
            ordinary: String::new(),
        })
    }
    fn entry(&self, node: &Node) -> Result<Entry> {
        if let Some(record) = &node.record {
            return Ok(Entry {
                name: name(&node.path).into(),
                path: node.path.clone(),
                is_directory: node.directory(),
                size: record.size,
                created_date: 0,
                updated_date: record.updated_date,
                is_hidden: false,
                is_symbolic_link: false,
                is_symbolic_link_known: false,
                reference: Some(reference_defaults(
                    &json!({"id":self.opaque(&record.entry_id),
                    "parentId":if record.parent_id.is_empty(){String::new()}else{self.opaque(&record.parent_id)},
                    "content":{"vaultId":self.reference.vault_id,"entryId":record.entry_id,"revisionId":record.operation_id,"ordinaryPath":""}}),
                )),
            });
        }
        let raw = node.raw.as_ref().ok_or(PlatformFailure)?;
        let anchor = node.anchor.as_ref().ok_or(PlatformFailure)?;
        let mut reference = reference_defaults(raw.reference.as_ref().unwrap_or(&json!({})));
        if ref_text(Some(&reference), "id").is_empty() {
            reference["id"] = json!(self.ordinary_opaque(&anchor.entry_id, &node.ordinary));
        }
        if ref_text(Some(&reference), "parentId").is_empty() {
            let suffix = node.ordinary.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            reference["parentId"] = json!(if suffix.is_empty() {
                self.opaque(&anchor.entry_id)
            } else {
                self.ordinary_opaque(&anchor.entry_id, suffix)
            });
        }
        reference["content"] = json!({"vaultId":self.reference.vault_id,"entryId":anchor.entry_id,"revisionId":anchor.operation_id,"ordinaryPath":node.ordinary});
        Ok(Entry {
            path: node.path.clone(),
            reference: Some(reference),
            ..raw.clone()
        })
    }
    fn logical_path(&self, path: &Path, view: &View) -> Result<String> {
        let identity = path
            .reference
            .as_ref()
            .and_then(|r| r.get("content"))
            .filter(|v| !v.is_null());
        let result = if let Some(identity) = identity {
            ensure!(
                identity["vaultId"] == self.reference.vault_id,
                changed("content reference belongs to another location")
            );
            let entry = identity["entryId"].as_str().unwrap_or("");
            let anchor = view
                .history
                .head(entry)?
                .ok_or_else(|| changed("authenticated entry disappeared"))?;
            ensure!(
                anchor.kind != Kind::Delete,
                changed("authenticated entry deleted")
            );
            let revision = identity["revisionId"].as_str().unwrap_or("");
            if !revision.is_empty() && revision != anchor.operation_id {
                let prior = view.history.records().get(revision);
                let same = prior.is_some_and(|r| {
                    r.entry_id == anchor.entry_id
                        && r.kind == anchor.kind
                        && match anchor.kind {
                            Kind::File => {
                                r.object_id == anchor.object_id
                                    && r.ciphertext_digest == anchor.ciphertext_digest
                                    && r.ciphertext_length == anchor.ciphertext_length
                                    && r.size == anchor.size
                            }
                            Kind::Directory | Kind::Root => {
                                r.ordinary_directory == anchor.ordinary_directory
                            }
                            Kind::Delete => false,
                        }
                });
                ensure!(
                    same,
                    changed("authenticated body or directory binding changed")
                );
            }
            let base = self.managed(anchor, view)?.path;
            let ordinary = identity["ordinaryPath"].as_str().unwrap_or("");
            if ordinary.is_empty() {
                base
            } else {
                ensure!(
                    matches!(anchor.kind, Kind::Root | Kind::Directory),
                    conflict("ordinary child has no authenticated directory")
                );
                for part in ordinary.split('/') {
                    validate_name(part)?;
                }
                let physical = match anchor.kind {
                    Kind::Root => Some(self.reference.root.clone()),
                    Kind::Directory => anchor
                        .ordinary_directory
                        .as_ref()
                        .map(|b| self.physical(b))
                        .transpose()?,
                    _ => None,
                };
                let candidate = physical.map(|p| join(&p.path, ordinary));
                let binding = if !revision.is_empty() {
                    candidate.as_ref().and_then(|candidate| {
                        view.bindings
                            .iter()
                            .filter(|(key, _)| {
                                *candidate == **key || candidate.starts_with(&prefix(key))
                            })
                            .max_by_key(|(key, _)| key.len())
                    })
                } else {
                    None
                };
                if let Some((binding, record)) = binding {
                    ensure!(
                        record.kind != Kind::Delete,
                        changed("ordinary source directory deleted")
                    );
                    let relocated = self.managed(record, view)?.path;
                    let candidate = candidate.as_ref().unwrap();
                    if candidate == binding {
                        relocated
                    } else {
                        join(
                            &relocated,
                            candidate.strip_prefix(&prefix(binding)).unwrap(),
                        )
                    }
                } else {
                    join(&base, ordinary)
                }
            }
        } else {
            canonical(&path.path)
        };
        ensure!(
            result == self.root || result.starts_with(&prefix(&self.root)),
            conflict("path outside password location")
        );
        let suffix = if result == self.root {
            ""
        } else {
            result.strip_prefix(&prefix(&self.root)).unwrap_or("")
        };
        ensure!(
            suffix.split('/').count() <= 256,
            conflict("logical depth exceeds traversal limit")
        );
        for part in suffix.split('/').filter(|s| !s.is_empty()) {
            validate_name(part)?;
        }
        ensure!(
            !suffix
                .split('/')
                .any(|p| matches!(p, NAMESPACE | ".folderspan-content.json")),
            conflict("reserved location material cannot be ordinary content")
        );
        Ok(result)
    }
    fn physical(&self, binding: &DirectoryBinding) -> Result<Path> {
        let path = join(&self.root, &binding.relative_path);
        let reference = if let Some(r) = &binding.reference {
            Some(r.clone())
        } else {
            self.reference
                .root
                .reference
                .as_ref()
                .map(|r| for_path(r, &self.root, &path, true))
                .transpose()?
                .flatten()
        };
        Ok(Path { path, reference })
    }
    fn relative_physical(&self, path: &str) -> Result<String> {
        let path = canonical(path);
        ensure!(
            path.starts_with(&prefix(&self.root)),
            conflict("backing escapes password location")
        );
        Ok(path.strip_prefix(&prefix(&self.root)).unwrap().to_owned())
    }
    fn child(&self, parent: &Path, name: &str) -> Result<Path> {
        validate_name(name)?;
        let mut parent = parent.clone();
        if let Some(reference) = &mut parent.reference {
            reference["content"] = Value::Null;
        }
        child_path(&parent, name)
    }
    fn opaque(&self, entry: &str) -> String {
        format!("fsp-content:{}:{entry}", self.reference.vault_id)
    }
    fn ordinary_opaque(&self, entry: &str, path: &str) -> String {
        format!("fsp-ordinary:{}:{entry}:{path}", self.reference.vault_id)
    }
}
