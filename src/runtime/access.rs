use super::config::{canonical_path, random_id, read_state, write_private};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const KEY_FILE: &str = "web-ui-key.sha256";
const STATE_LIMIT: u64 = 256 * 1024;
const MAX_KEYS: usize = 64;
const MAX_DIRECTORIES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Storage,
    Devices,
    Shares,
    Mcp,
    OutboundHttp,
}

impl Feature {
    pub const ALL: [Self; 5] = [
        Self::Storage,
        Self::Devices,
        Self::Shares,
        Self::Mcp,
        Self::OutboundHttp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Storage => "Network storage",
            Self::Devices => "Devices",
            Self::Shares => "File sharing",
            Self::Mcp => "MCP",
            Self::OutboundHttp => "Outbound HTTP",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGrant {
    pub path: PathBuf,
    pub write: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Access {
    #[default]
    Full,
    Scoped {
        features: BTreeSet<Feature>,
        directories: Vec<DirectoryGrant>,
    },
}

impl Access {
    pub fn allows(&self, feature: Feature) -> bool {
        match self {
            Self::Full => true,
            Self::Scoped { features, .. } => features.contains(&feature),
        }
    }

    pub fn require(&self, feature: Feature) -> Result<()> {
        ensure!(
            self.allows(feature),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        );
        Ok(())
    }

    pub fn directories(&self) -> Option<&[DirectoryGrant]> {
        match self {
            Self::Full => None,
            Self::Scoped { directories, .. } => Some(directories),
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(directories) = self.directories() {
            ensure!(
                directories.len() <= MAX_DIRECTORIES,
                "too many directory grants"
            );
            let mut paths = BTreeSet::new();
            for grant in directories {
                ensure!(
                    grant.path.is_absolute()
                        && grant
                            .path
                            .to_str()
                            .is_some_and(|p| !p.chars().any(char::is_control))
                        && !grant.path.components().any(|c| c == Component::ParentDir)
                        && paths.insert(&grant.path),
                    "invalid or duplicate directory grant"
                );
            }
        }
        Ok(())
    }

    fn normalize(&mut self) -> Result<()> {
        if let Self::Scoped { directories, .. } = self {
            for grant in directories {
                ensure!(grant.path.is_absolute(), "grant directory must be absolute");
                grant.path = canonical_path(&grant.path)
                    .map_err(|_| anyhow::anyhow!("grant directory is unavailable"))?;
                ensure!(grant.path.is_dir(), "grant must select a directory");
            }
        }
        self.validate()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub id: String,
    pub name: String,
    pub access: Access,
    digest: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    version: u32,
    keys: Vec<Key>,
}

impl Credentials {
    pub fn load(dir: &Path) -> Result<Self> {
        let Some(bytes) = read_state(&dir.join(KEY_FILE), STATE_LIMIT)? else {
            return Ok(Self {
                version: 1,
                keys: Vec::new(),
            });
        };
        if let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(Self {
                version: 1,
                keys: vec![Key {
                    id: "legacy".into(),
                    name: "Default".into(),
                    access: Access::Full,
                    digest,
                }],
            });
        }
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid credential file"))?;
        state.validate()?;
        Ok(state)
    }

    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    pub fn authorize(&self, secret: &str) -> Option<Access> {
        let secret = secret.trim();
        if secret.is_empty() || secret.starts_with("fmcp_") {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let mut matched = None;
        for key in &self.keys {
            if bool::from(key.digest.ct_eq(&digest)) {
                matched = Some(&key.access);
            }
        }
        matched.cloned()
    }

    pub fn add(&mut self, name: String, mut access: Access) -> Result<Zeroizing<String>> {
        ensure!(self.keys.len() < MAX_KEYS, "too many Web credentials");
        access.normalize()?;
        let id = random_id(16);
        let name = self.valid_name(&id, name)?;
        let (digest, secret) = generate();
        self.keys.push(Key {
            id,
            name,
            access,
            digest,
        });
        Ok(secret)
    }

    pub fn edit(&mut self, id: &str, name: String, mut access: Access) -> Result<()> {
        access.normalize()?;
        let name = self.valid_name(id, name)?;
        let key = self.get_mut(id)?;
        key.name = name;
        key.access = access;
        Ok(())
    }

    pub fn rotate(&mut self, id: &str) -> Result<Zeroizing<String>> {
        let (digest, secret) = generate();
        self.get_mut(id)?.digest = digest;
        Ok(secret)
    }

    pub fn revoke(&mut self, id: &str) -> Result<()> {
        ensure!(
            self.keys.len() > 1,
            "create a replacement before revoking the last key"
        );
        let index = self
            .keys
            .iter()
            .position(|key| key.id == id)
            .ok_or_else(|| anyhow::anyhow!("the selected key was changed"))?;
        self.keys.remove(index);
        Ok(())
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() as u64 <= STATE_LIMIT,
            "credential file exceeds size limit"
        );
        write_private(&dir.join(KEY_FILE), &bytes)
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut Key> {
        self.keys
            .iter_mut()
            .find(|key| key.id == id)
            .ok_or_else(|| anyhow::anyhow!("the selected key no longer exists"))
    }

    fn valid_name(&self, id: &str, name: String) -> Result<String> {
        let name = name.trim();
        ensure!(
            (1..=80).contains(&name.chars().count())
                && !name.chars().any(char::is_control)
                && !self.keys.iter().any(|key| key.id != id && key.name == name),
            "enter a unique key name of 1 to 80 characters"
        );
        Ok(name.to_owned())
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && (1..=MAX_KEYS).contains(&self.keys.len()),
            "unsupported credential file"
        );
        let mut ids = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for key in &self.keys {
            ensure!(
                (key.id == "legacy"
                    || (key.id.len() == 32 && key.id.bytes().all(|b| b.is_ascii_hexdigit())))
                    && ids.insert(&key.id)
                    && digests.insert(key.digest),
                "invalid or duplicate credential"
            );
            self.valid_name(&key.id, key.name.clone())?;
            key.access.validate()?;
        }
        Ok(())
    }
}

fn generate() -> ([u8; 32], Zeroizing<String>) {
    let secret = Zeroizing::new(format!("fwui_{}_{}", random_id(8), random_id(32)));
    (Sha256::digest(secret.as_bytes()).into(), secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_migrates_and_keys_rotate_independently() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let legacy = "fwui_old_key";
        write_private(&root.join(KEY_FILE), &Sha256::digest(legacy.as_bytes())).unwrap();
        let mut credentials = Credentials::load(root).unwrap();
        assert_eq!(credentials.authorize(legacy), Some(Access::Full));
        assert_eq!(std::fs::metadata(root.join(KEY_FILE)).unwrap().len(), 32);
        let scoped = Access::Scoped {
            features: BTreeSet::from([Feature::Shares]),
            directories: vec![],
        };
        let key = credentials.add("Sharing".into(), scoped.clone()).unwrap();
        credentials.save(root).unwrap();

        let mut credentials = Credentials::load(root).unwrap();
        assert_eq!(credentials.authorize(&key), Some(scoped.clone()));
        let id = credentials.keys()[1].id.clone();
        credentials
            .edit(&id, "File relay".into(), scoped.clone())
            .unwrap();
        let updated = credentials.rotate(&id).unwrap();
        assert_eq!(credentials.authorize(&key), None);
        assert_eq!(credentials.authorize(&updated), Some(scoped));
        assert_eq!(credentials.authorize(legacy), Some(Access::Full));
        credentials.revoke(&id).unwrap();
        credentials.save(root).unwrap();
        let mut credentials = Credentials::load(root).unwrap();
        assert_eq!(credentials.authorize(&updated), None);
        assert!(credentials.revoke("legacy").is_err());
        assert!(
            !std::fs::read_to_string(root.join(KEY_FILE))
                .unwrap()
                .contains(legacy)
        );
    }
}
