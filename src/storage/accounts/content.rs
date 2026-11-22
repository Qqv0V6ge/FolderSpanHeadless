use super::Storage;
use crate::storage::content_crypto::{ContentError, ErrorCode};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

impl Storage {
    pub(crate) fn authorization_generation(&self, protocol: &str, id: &str) -> String {
        if !["GoogleDrive", "Dropbox", "Nextcloud", "Seafile"].contains(&protocol)
            || super::account_id(id).is_err()
        {
            return String::new();
        }
        self.state
            .lock()
            .unwrap()
            .generations
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn content_prefix(&self, prefix: &str) -> BTreeMap<String, Zeroizing<String>> {
        self.state
            .lock()
            .unwrap()
            .content
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
    pub(crate) fn content_setting(&self, name: &str) -> Option<Zeroizing<String>> {
        self.state.lock().unwrap().content.get(name).cloned()
    }
    pub(crate) fn content_transaction<T>(
        &self,
        change: impl FnOnce(&mut BTreeMap<String, Zeroizing<String>>) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let result = change(&mut next.content)?;
        self.save(&next)?;
        *state = next;
        Ok(result)
    }
}

fn version() -> u32 {
    1
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default = "version")]
    version: u32,
    key: Zeroizing<String>,
}
type UnlockedKeys = BTreeMap<(String, String), Zeroizing<[u8; 32]>>;

/// Persisted key identity does not grant an unlock; each content context owns its memory-only grants.
pub struct PasswordKeys {
    store: Arc<Storage>,
    unlocked: Mutex<UnlockedKeys>,
}
fn name(scope: &str) -> Result<String> {
    ensure!(
        (1..=4096).contains(&scope.len()),
        "invalid encrypted location"
    );
    Ok("auth.storage.password-location.key.".to_owned()
        + &hex::encode(Sha256::digest(scope.as_bytes())))
}
impl PasswordKeys {
    pub fn new(store: Arc<Storage>) -> Self {
        Self {
            store,
            unlocked: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn unlock(
        &self,
        scope: &str,
        owner: &str,
        authorization_owner: &str,
        key: &[u8; 32],
    ) -> Result<()> {
        ensure!(
            !owner.trim().is_empty()
                && (owner == authorization_owner
                    || owner.starts_with(&(authorization_owner.to_owned() + "|"))),
            "invalid password authorization owner"
        );
        let name = name(scope)?;
        let mut unlocked = self.unlocked.lock().unwrap();
        self.store.content_transaction(|settings| {
            if let Some(value) = settings.get(&name) {
                let record: Record = serde_json::from_str(value)?;
                ensure!(
                    record.version == 1,
                    "unsupported password location key record"
                );
                let existing = Zeroizing::new(STANDARD.decode(record.key.as_bytes())?);
                ensure!(
                    bool::from(existing.as_slice().ct_eq(key)),
                    "password location recovery would replace a different content key"
                );
            }
            let record = Record {
                version: 1,
                key: Zeroizing::new(STANDARD.encode(key)),
            };
            settings.insert(name, Zeroizing::new(serde_json::to_string(&record)?));
            Ok(())
        })?;
        retire(&mut unlocked, scope, authorization_owner);
        unlocked.insert((scope.to_owned(), owner.to_owned()), Zeroizing::new(*key));
        Ok(())
    }
    pub fn status(&self, scope: &str, owner: &str) -> Result<(bool, bool)> {
        let unlocked = self.unlocked.lock().unwrap();
        Ok((
            self.store.content_setting(&name(scope)?).is_some(),
            unlocked.contains_key(&(scope.to_owned(), owner.to_owned())),
        ))
    }
    pub fn key(&self, scope: &str, owner: &str) -> Result<Zeroizing<[u8; 32]>> {
        self.unlocked
            .lock()
            .unwrap()
            .get(&(scope.to_owned(), owner.to_owned()))
            .map(|value| Zeroizing::new(**value))
            .ok_or_else(|| {
                ContentError(
                    ErrorCode::Locked,
                    "password location is locked; enter its content password",
                )
                .into()
            })
    }
    pub fn lock(&self, scope: &str, authorization_owner: &str) {
        retire(
            &mut self.unlocked.lock().unwrap(),
            scope,
            authorization_owner,
        );
    }
    pub fn close(&self) {
        self.unlocked.lock().unwrap().clear();
    }
}
fn retire(unlocked: &mut UnlockedKeys, scope: &str, owner: &str) {
    unlocked.retain(|(vault, value), _| {
        vault != scope || !(value == owner || value.starts_with(&(owner.to_owned() + "|")))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_survive_restart_but_unlocks_are_context_and_authorization_owned() {
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        let keys = PasswordKeys::new(store.clone());
        assert_eq!(keys.status("scope", "account|1").unwrap(), (false, false));
        keys.unlock("scope", "account|1", "account", &[7; 32])
            .unwrap();
        assert_eq!(*keys.key("scope", "account|1").unwrap(), [7; 32]);
        assert!(keys.key("scope", "account|2").is_err());
        let isolated = PasswordKeys::new(store.clone());
        assert_eq!(
            isolated.status("scope", "account|1").unwrap(),
            (true, false)
        );
        assert!(isolated.key("scope", "account|1").is_err());
        assert!(
            keys.unlock("scope", "account|2", "account", &[8; 32])
                .is_err()
        );
        assert_eq!(*keys.key("scope", "account|1").unwrap(), [7; 32]);
        keys.unlock("scope", "account|2", "account", &[7; 32])
            .unwrap();
        assert!(keys.key("scope", "account|1").is_err());
        keys.unlock("scope", "other|1", "other", &[7; 32]).unwrap();
        keys.lock("scope", "account");
        assert!(keys.key("scope", "account|2").is_err());
        assert_eq!(*keys.key("scope", "other|1").unwrap(), [7; 32]);
        keys.close();
        assert!(keys.key("scope", "other|1").is_err());
        drop(keys);
        drop(isolated);
        drop(store);
        let recovered = PasswordKeys::new(Storage::load(root.path()).unwrap());
        assert_eq!(
            recovered.status("scope", "account|2").unwrap(),
            (true, false)
        );
        recovered
            .unlock("scope", "account|2", "account", &[7; 32])
            .unwrap();
        assert_eq!(*recovered.key("scope", "account|2").unwrap(), [7; 32]);
        let bytes = std::fs::read(root.path().join("storage-accounts.json")).unwrap();
        let plain_key = STANDARD.encode([7; 32]);
        assert!(
            !bytes
                .windows(plain_key.len())
                .any(|v| v == plain_key.as_bytes())
        );
        assert!(bytes.starts_with(crate::storage::accounts::cipher::MAGIC));
    }
    #[test]
    fn failed_key_or_setting_persistence_never_changes_the_admitted_memory_state() {
        let root = tempfile::tempdir().unwrap();
        let store = Storage::load(root.path()).unwrap();
        let keys = PasswordKeys::new(store.clone());
        keys.unlock("scope", "account|1", "account", &[7; 32])
            .unwrap();
        let before = std::fs::read(&store.path).unwrap();
        std::fs::rename(&store.path, root.path().join("previous")).unwrap();
        std::fs::create_dir(&store.path).unwrap();
        assert!(
            keys.unlock("scope", "account|2", "account", &[7; 32])
                .is_err()
        );
        assert_eq!(*keys.key("scope", "account|1").unwrap(), [7; 32]);
        assert!(keys.key("scope", "account|2").is_err());
        assert!(
            store
                .content_transaction(|settings| {
                    settings.insert("pending".into(), Zeroizing::new("new".into()));
                    Ok(())
                })
                .is_err()
        );
        assert!(store.content_setting("pending").is_none());
        assert_eq!(std::fs::read(root.path().join("previous")).unwrap(), before);
        assert!(
            keys.unlock("other", "unrelated", "account", &[7; 32])
                .is_err()
        );
    }
}
