//! Authenticated append records and deterministic conflict-preserving password-location history.
use crate::storage::content_crypto::{ContentError, ErrorCode, canonical_uuid};
use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"FolderSpan commit authentication v1\0";
pub const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Kind {
    Root,
    File,
    Directory,
    Delete,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryBinding {
    pub relative_path: String,
    #[serde(
        default,
        serialize_with = "crate::storage::remote::serialize_reference",
        deserialize_with = "crate::storage::remote::deserialize_reference"
    )]
    pub reference: Option<Value>,
}
fn version() -> i32 {
    1
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Commit {
    #[serde(default = "version")]
    pub version: i32,
    pub vault_id: String,
    pub operation_id: String,
    pub entry_id: String,
    pub parent_id: String,
    pub name: String,
    #[serde(default)]
    pub parents: Vec<String>,
    pub kind: Kind,
    #[serde(default)]
    pub object_id: String,
    #[serde(default)]
    pub ciphertext_length: i64,
    #[serde(default)]
    pub ciphertext_digest: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub updated_date: i64,
    #[serde(default)]
    pub ordinary_directory: Option<DirectoryBinding>,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
}
impl Commit {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported content commit version");
        for id in [&self.vault_id, &self.operation_id, &self.entry_id] {
            canonical_uuid(id)?;
        }
        ensure!(
            self.parents.len() <= 64
                && self.parents.iter().collect::<BTreeSet<_>>().len() == self.parents.len()
                && !self.parents.contains(&self.operation_id),
            "invalid content parent revisions"
        );
        for id in &self.parents {
            canonical_uuid(id)?;
        }
        ensure!(
            self.size >= 0 && self.updated_date >= 0,
            "invalid content metadata"
        );
        if let Some(binding) = &self.ordinary_directory {
            ensure!(
                matches!(self.kind, Kind::Directory | Kind::Delete),
                "invalid directory binding"
            );
            ensure!(
                !binding.relative_path.trim().is_empty()
                    && !binding.relative_path.starts_with('/')
                    && binding
                        .relative_path
                        .split('/')
                        .all(|part| !part.trim().is_empty() && part != ".folderspan-vault")
                    && !control(&binding.relative_path),
                "invalid ordinary directory binding"
            );
            crate::storage::remote::validate_write_path(
                &("/".to_owned() + &binding.relative_path),
            )?;
            crate::storage::remote::validate_reference(binding.reference.as_ref())?;
            ensure!(
                binding.reference.as_ref().is_none_or(|r| r
                    .get("content")
                    .is_none_or(Value::is_null)
                    && r.get("ancestorPath")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)),
                "directory binding contains a local context"
            );
        }
        if self.kind == Kind::Root {
            ensure!(
                self.entry_id == self.vault_id
                    && self.parent_id.is_empty()
                    && self.name.is_empty()
                    && self.parents.is_empty()
                    && self.object_id.is_empty()
                    && self.ciphertext_length == 0
                    && self.size == 0,
                "invalid content root record"
            );
            ensure!(
                digest(&self.ciphertext_digest),
                "missing password descriptor binding"
            );
        } else {
            canonical_uuid(&self.parent_id)?;
            ensure!(
                self.entry_id != self.vault_id
                    && self.entry_id != self.parent_id
                    && !self.name.trim().is_empty()
                    && self.name.encode_utf16().count() <= 255
                    && !self.name.contains(['/', '\\'])
                    && !control(&self.name),
                "invalid content entry name or parent"
            );
            crate::storage::remote::validate_write_path(&("/".to_owned() + &self.name))?;
            if self.kind == Kind::File {
                canonical_uuid(&self.object_id)?;
                ensure!(
                    self.ciphertext_length >= 160 && digest(&self.ciphertext_digest),
                    "invalid ciphertext object binding"
                );
            } else {
                ensure!(
                    self.object_id.is_empty()
                        && self.ciphertext_length == 0
                        && self.ciphertext_digest.is_empty()
                        && self.size == 0,
                    "unexpected content object in metadata record"
                );
            }
        }
        Ok(())
    }
}
fn authenticate(key: &[u8; 32], prefix: &[u8]) -> Result<[u8; 32]> {
    let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(key)?;
    derive.update(DOMAIN);
    let derived = Zeroizing::new(<[u8; 32]>::from(derive.finalize().into_bytes()));
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(derived.as_ref())?;
    mac.update(prefix);
    Ok(mac.finalize().into_bytes().into())
}
pub fn encode(record: &Commit, key: &[u8; 32]) -> Result<Vec<u8>> {
    record.validate()?;
    let payload = serde_json::to_vec(record)?;
    ensure!(payload.len() <= 64 * 1024, "content commit is too large");
    let mut bytes = Vec::with_capacity(payload.len() + 48);
    bytes.extend_from_slice(b"FSPANCMT");
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&authenticate(key, &bytes)?);
    Ok(bytes)
}
pub fn decode(bytes: &[u8], key: &[u8; 32], vault_id: &str) -> Result<Commit> {
    let result = (|| -> Result<Commit> {
        ensure!(
            (48..=64 * 1024 + 48).contains(&bytes.len()),
            "invalid content commit length"
        );
        if &bytes[..8] != b"FSPANCMT" || bytes[8..12] != 1u32.to_be_bytes() {
            return Err(ContentError(
                ErrorCode::UnsupportedFormat,
                "unsupported content commit format",
            )
            .into());
        }
        let length = u32::from_be_bytes(bytes[12..16].try_into()?) as usize;
        ensure!(
            length <= 64 * 1024 && bytes.len() == length + 48,
            "invalid content commit payload length"
        );
        let expected = Zeroizing::new(authenticate(key, &bytes[..length + 16])?);
        use subtle::ConstantTimeEq;
        ensure!(
            bool::from(expected.as_ref().ct_eq(&bytes[length + 16..])),
            "content commit authentication failed"
        );
        let record: Commit = serde_json::from_slice(&bytes[16..length + 16])?;
        record.validate()?;
        ensure!(
            record.vault_id == vault_id,
            "content commit belongs to another location"
        );
        Ok(record)
    })();
    result.map_err(|e| {
        if e.is::<ContentError>() {
            e
        } else {
            ContentError(
                ErrorCode::DamagedLocation,
                "authenticated content metadata is damaged",
            )
            .into()
        }
    })
}
pub fn object_scope(vault_id: &str, object_id: &str) -> Result<String> {
    canonical_uuid(vault_id)?;
    canonical_uuid(object_id)?;
    Ok("FolderSpan vault object v1\0".to_owned() + &serde_json::to_string(&[vault_id, object_id])?)
}

pub struct History {
    vault_id: String,
    records: BTreeMap<String, Commit>,
    heads: BTreeMap<String, Vec<String>>,
}
impl History {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn records(&self) -> &BTreeMap<String, Commit> {
        &self.records
    }
    pub fn heads(&self) -> &BTreeMap<String, Vec<String>> {
        &self.heads
    }
    pub fn replay(vault_id: &str, input: Vec<Commit>) -> Result<Self> {
        ensure!(
            (1..=MAX_RECORDS).contains(&input.len()),
            "content history is missing or exceeds the replay limit"
        );
        for record in &input {
            record.validate()?;
            ensure!(
                record.vault_id == vault_id,
                "content history contains another location"
            );
        }
        let mut heads = BTreeMap::<String, Vec<String>>::new();
        for record in &input {
            heads
                .entry(record.entry_id.clone())
                .or_default()
                .push(record.operation_id.clone());
        }
        let roots: Vec<_> = input.iter().filter(|r| r.kind == Kind::Root).collect();
        ensure!(
            roots.len() == 1 && roots[0].operation_id == vault_id,
            "content history root is invalid"
        );
        let count = input.len();
        let records: BTreeMap<_, _> = input
            .into_iter()
            .map(|r| (r.operation_id.clone(), r))
            .collect();
        ensure!(
            records.len() == count,
            "content history repeats an operation identity"
        );
        let mut children = BTreeMap::<&str, Vec<&str>>::new();
        let mut remaining = BTreeMap::<&str, usize>::new();
        let mut ready = VecDeque::new();
        for record in records.values() {
            if record.kind != Kind::Root {
                ensure!(
                    heads.contains_key(&record.parent_id),
                    "content history parent directory is missing"
                );
                ensure!(
                    record.kind != Kind::Delete || !record.parents.is_empty(),
                    "content deletion must reference observed revisions"
                );
            }
            remaining.insert(&record.operation_id, record.parents.len());
            if record.parents.is_empty() {
                ready.push_back(record.operation_id.as_str());
            }
            for id in &record.parents {
                let parent = records
                    .get(id)
                    .ok_or_else(|| anyhow::anyhow!("content history parent revision is missing"))?;
                ensure!(
                    parent.entry_id == record.entry_id,
                    "content revision belongs to another entry"
                );
                children.entry(id).or_default().push(&record.operation_id);
            }
        }
        let mut visited = 0;
        while let Some(id) = ready.pop_front() {
            visited += 1;
            for child in children.get(id).into_iter().flatten() {
                let count = remaining.get_mut(child).unwrap();
                *count -= 1;
                if *count == 0 {
                    ready.push_back(child);
                }
            }
        }
        ensure!(visited == count, "content revision graph contains a cycle");
        let consumed: BTreeSet<_> = records.values().flat_map(|r| r.parents.iter()).collect();
        for revisions in heads.values_mut() {
            revisions.retain(|r| !consumed.contains(r));
        }
        Ok(Self {
            vault_id: vault_id.to_owned(),
            records,
            heads,
        })
    }
    pub fn head(&self, entry_id: &str) -> Result<Option<&Commit>> {
        let revisions = self.heads.get(entry_id).map(Vec::as_slice).unwrap_or(&[]);
        if revisions.len() > 1 {
            return Err(ContentError(
                ErrorCode::Conflict,
                "this entry has concurrent revisions; preserve all branches",
            )
            .into());
        }
        Ok(revisions.first().map(|id| &self.records[id]))
    }
    pub fn path(&self, record: &Commit) -> Result<String> {
        let mut names = Vec::new();
        let mut visited = BTreeSet::new();
        let mut current = record;
        let mut length = 0;
        while current.kind != Kind::Root {
            ensure!(
                visited.insert(&current.entry_id),
                "content directory hierarchy contains a cycle"
            );
            ensure!(
                current.kind != Kind::Delete,
                "a deleted directory still has live children"
            );
            names.push(current.name.as_str());
            length += current.name.encode_utf16().count() + 1;
            ensure!(length <= 16 * 1024, "content logical path is too long");
            current = self
                .head(&current.parent_id)?
                .ok_or_else(|| anyhow::anyhow!("content parent directory is missing"))?;
            ensure!(
                matches!(current.kind, Kind::Root | Kind::Directory),
                "content parent is not a live directory"
            );
        }
        names.reverse();
        Ok("/".to_owned() + &names.join("/"))
    }
    pub fn live_entries(&self) -> Result<Vec<&Commit>> {
        let mut live = Vec::new();
        let mut names = BTreeSet::new();
        for id in self.heads.keys() {
            if let Some(record) = self.head(id)? {
                if matches!(record.kind, Kind::Root | Kind::Delete) {
                    continue;
                }
                ensure!(
                    names.insert((&record.parent_id, &record.name)),
                    "concurrent entries have the same logical name"
                );
                self.path(record)?;
                live.push(record);
            }
        }
        Ok(live)
    }
}
#[cfg(test)]
mod tests;
