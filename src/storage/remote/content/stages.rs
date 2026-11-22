use super::{FileInfo, Protocol, Request, Sensitivity, new_uuid};
use crate::{
    management::reply::{Reply, ResourceUnavailable},
    runtime::config,
    storage::{accounts::Storage, files},
};
use anyhow::{Context as _, Result, ensure};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Registration {
    consumed: bool,
    task: i64,
    identity: String,
}
#[derive(Clone)]
struct Cipher {
    registration: Registration,
    entry: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskMapping {
    #[serde(default = "super::version")]
    version: i32,
    task_key: i64,
    reference: String,
    runtime_task_key: i64,
}
pub(super) struct Stages {
    root: PathBuf,
    tasks: BTreeMap<i64, (String, i64)>,
    plain: BTreeMap<PathBuf, Registration>,
    cipher: BTreeMap<PathBuf, Cipher>,
}
fn unavailable(message: &'static str) -> anyhow::Error {
    ResourceUnavailable(message).into()
}
pub(super) fn normalized(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut result = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            part => result.push(part.as_os_str()),
        }
    }
    Ok(result)
}
fn identity(file: &std::fs::File) -> Result<String> {
    let (device, inode) = files::file_identity(file)
        .context(ResourceUnavailable("private file identity unavailable"))?;
    Ok(format!("{device}:{inode}"))
}
pub(super) fn raw_file(path: &Path, write: bool) -> Result<std::fs::File> {
    let (parent, name, _) = files::open_parent_nofollow(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(write).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options)?.into_std();
    ensure!(
        file.metadata()?.is_file(),
        unavailable("private stage is not an ordinary file")
    );
    Ok(file)
}
impl Stages {
    pub fn new(root: PathBuf) -> Result<Self> {
        Ok(Self {
            root: normalized(&root)?,
            tasks: BTreeMap::new(),
            plain: BTreeMap::new(),
            cipher: BTreeMap::new(),
        })
    }
    pub fn task(&mut self, store: &Storage, input: &Request, create: bool) -> Result<i64> {
        crate::storage::content_crypto::canonical_uuid(&input.task_reference)?;
        if let Some((reference, task)) = self.tasks.get(&input.task_key) {
            ensure!(
                *reference == input.task_reference,
                "content task reference changed"
            );
            return Ok(*task);
        }
        ensure!(create, "unknown content encryption task");
        let name = "auth.storage.content.task.".to_owned() + &input.task_reference;
        let task = store.content_transaction(|settings| {
            if let Some(record) = settings.get(&name) {
                let record: TaskMapping = serde_json::from_str(record)?;
                ensure!(
                    record.version == 1
                        && record.task_key == input.task_key
                        && record.reference == input.task_reference,
                    "content task identity changed"
                );
                return Ok(record.runtime_task_key);
            }
            let bytes = crate::storage::content_crypto::canonical_uuid(&new_uuid()?)?;
            let task = i64::from_be_bytes(bytes[..8].try_into()?);
            let record = TaskMapping {
                version: 1,
                task_key: input.task_key,
                reference: input.task_reference.clone(),
                runtime_task_key: task,
            };
            settings.insert(name, Zeroizing::new(serde_json::to_string(&record)?));
            Ok(task)
        })?;
        self.tasks
            .insert(input.task_key, (input.task_reference.clone(), task));
        Ok(task)
    }
    pub fn known_task(&self, key: i64) -> bool {
        self.tasks.contains_key(&key)
    }
    fn directory(&self, task: i64) -> Result<PathBuf> {
        config::private_directory(&self.root)?;
        let directory = self.root.join(task.to_string());
        config::private_directory(&directory)?;
        // Validate every component before using a task directory, including an existing cache root.
        files::open_parent_nofollow(&directory.join(".probe"))?;
        Ok(directory)
    }
    pub fn create(&mut self, task: i64) -> Result<String> {
        let directory = self.directory(task)?;
        let path = directory.join(format!(".input-{}.part", new_uuid()?));
        let (parent, name, _) = files::open_parent_nofollow(&path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NONBLOCK);
        }
        let file = parent.open_with(&name, &options)?.into_std();
        let result = (|| -> Result<String> {
            config::restrict_private(&path, false)?;
            let id = identity(&file)?;
            ensure!(
                identity(&raw_file(&path, false)?)? == id,
                unavailable("private staging ownership changed")
            );
            self.plain.insert(
                path.clone(),
                Registration {
                    task,
                    identity: id,
                    consumed: false,
                },
            );
            Ok(path.to_string_lossy().into_owned())
        })();
        if result.is_err() {
            let _ = parent.remove_file(name);
        }
        result
    }
    fn admitted(&self, task: i64, path: &str, plain_only: bool) -> Result<(PathBuf, Registration)> {
        let path = normalized(Path::new(path))?;
        let registration = self
            .plain
            .get(&path)
            .cloned()
            .or_else(|| {
                if plain_only {
                    None
                } else {
                    self.cipher.get(&path).map(|v| v.registration.clone())
                }
            })
            .context("unknown private content stage")?;
        ensure!(
            registration.task == task
                && path.parent() == Some(self.root.join(task.to_string()).as_path()),
            "content stage belongs to another task"
        );
        Ok((path, registration))
    }
    pub fn is_plain(&self, task: i64, path: &str) -> bool {
        normalized(Path::new(path))
            .ok()
            .and_then(|p| self.plain.get(&p))
            .is_some_and(|r| r.task == task)
    }
    pub fn open(&self, task: i64, path: &str, write: bool) -> Result<std::fs::File> {
        let (path, registration) = self.admitted(task, path, write)?;
        ensure!(
            !registration.consumed,
            unavailable("private stage was consumed")
        );
        self.directory(task)?;
        let file =
            raw_file(&path, write).map_err(|_| unavailable("private staging ownership changed"))?;
        ensure!(
            identity(&file)? == registration.identity,
            unavailable("private staging ownership changed")
        );
        Ok(file)
    }
    pub fn identity(&self, task: i64, path: &str) -> Result<String> {
        identity(&self.open(task, path, false)?)
    }
    pub fn complete(&mut self, task: i64, path: &str, expected: &str) -> Result<()> {
        let (path, registration) = self.admitted(task, path, true)?;
        ensure!(
            !registration.consumed && registration.identity == expected,
            unavailable("private stage write ownership changed")
        );
        self.directory(task)?;
        let file = raw_file(&path, true)
            .map_err(|_| unavailable("private stage is no longer an ordinary file"))?;
        config::restrict_private(&path, false)?;
        self.plain.insert(
            path,
            Registration {
                task,
                identity: identity(&file)?,
                consumed: false,
            },
        );
        Ok(())
    }
    pub fn remember_cipher(&mut self, task: i64, entry: &str, path: &str) -> Result<()> {
        let path = normalized(Path::new(path))?;
        ensure!(
            path.parent() == Some(self.root.join(task.to_string()).as_path())
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".cipher-")),
            "invalid encrypted staging path"
        );
        let id = identity(&raw_file(&path, false)?)?;
        self.cipher.insert(
            path,
            Cipher {
                registration: Registration {
                    task,
                    identity: id,
                    consumed: false,
                },
                entry: entry.to_owned(),
            },
        );
        Ok(())
    }
    pub fn revoke_cipher(&mut self, task: i64, entry: &str) {
        self.cipher
            .retain(|_, value| value.registration.task != task || value.entry != entry);
    }
    pub fn cipher_path(&self, task: i64, path: &str) -> Result<PathBuf> {
        let path = normalized(Path::new(path))?;
        ensure!(
            path.parent() == Some(self.directory(task)?.as_path())
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".cipher-")),
            "invalid encrypted spool path"
        );
        raw_file(&path, false)?;
        Ok(path)
    }
    pub fn new_cipher(&self, task: i64) -> Result<(PathBuf, std::fs::File)> {
        let path = self
            .directory(task)?
            .join(format!(".cipher-{}.part", new_uuid()?));
        let (parent, name, _) = files::open_parent_nofollow(&path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NONBLOCK);
        }
        let file = parent.open_with(name, &options)?.into_std();
        if let Err(error) = config::restrict_private(&path, false) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        Ok((path, file))
    }
    pub fn registered_plain(&self, path: &str) -> bool {
        normalized(Path::new(path))
            .ok()
            .is_some_and(|p| self.plain.contains_key(&p))
    }
    pub fn remove_plain(&mut self, task: i64, path: &str) -> Result<()> {
        let path = normalized(Path::new(path))?;
        if let Some(registration) = self
            .plain
            .get_mut(&path)
            .filter(|r| r.task == task && !r.consumed)
        {
            registration.consumed = true;
            if raw_file(&path, false)
                .and_then(|f| identity(&f))
                .ok()
                .as_deref()
                == Some(registration.identity.as_str())
            {
                let (parent, name, _) = files::open_parent_nofollow(&path)?;
                parent.remove_file(name)?;
            }
        }
        Ok(())
    }
    pub fn refresh_destination(&mut self, task: i64, path: &str) -> Result<()> {
        if self.is_plain(task, path) {
            let path = normalized(Path::new(path))?;
            let id = identity(&raw_file(&path, false)?)?;
            self.plain.insert(
                path,
                Registration {
                    task,
                    identity: id,
                    consumed: false,
                },
            );
        }
        Ok(())
    }
    pub fn close(&mut self) {
        let registrations = std::mem::take(&mut self.plain);
        for (path, registration) in registrations {
            if !registration.consumed
                && raw_file(&path, false)
                    .and_then(|f| identity(&f))
                    .ok()
                    .as_deref()
                    == Some(registration.identity.as_str())
            {
                if let Ok((parent, name, _)) = files::open_parent_nofollow(&path) {
                    let _ = parent.remove_file(name);
                }
            }
        }
        self.cipher.clear();
    }
    pub fn cleanup(&mut self, store: &Storage, input: &Request) -> Result<()> {
        let task = self.task(store, input, false)?;
        ensure!(
            !store.content_has_uncertain_task(task)?,
            unavailable("upload completion uncertain; preserve content evidence")
        );
        let mut names = Vec::new();
        for (name, bytes) in store.content_prefix("auth.storage.password-location.spool.") {
            let value: serde_json::Value = serde_json::from_str(&bytes)?;
            if value["taskKey"].as_i64() == Some(task) {
                ensure!(
                    value.get("record").is_none_or(serde_json::Value::is_null)
                        || value["completed"] == true,
                    unavailable(
                        "verify the original content operation before cleaning recovery evidence"
                    )
                );
                names.push(name);
            }
        }
        let paths: Vec<_> = self
            .plain
            .iter()
            .filter(|(_, r)| r.task == task)
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        for path in paths {
            self.remove_plain(task, &path)?;
        }
        let directory = self.root.join(task.to_string());
        match std::fs::symlink_metadata(&directory) {
            Ok(meta) => {
                ensure!(
                    meta.is_dir() && !meta.file_type().is_symlink(),
                    unavailable("content cache ownership changed")
                );
                let (parent, name, _) = files::open_parent_nofollow(&directory)?;
                parent.remove_dir_all(name)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if !names.is_empty() {
            store.content_transaction(|settings| {
                for name in names {
                    settings.remove(&name);
                }
                Ok(())
            })?;
        }
        self.cipher
            .retain(|_, value| value.registration.task != task);
        self.tasks.remove(&input.task_key);
        Ok(())
    }
    pub fn private_file(
        &mut self,
        method: &str,
        query: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> Result<Reply> {
        let task_key = query
            .get("taskKey")
            .context("task key required")?
            .parse::<i64>()?;
        let reference = query
            .get("taskReference")
            .context("task reference required")?;
        crate::storage::content_crypto::canonical_uuid(reference)?;
        let (expected, task) = self.tasks.get(&task_key).context("unknown content task")?;
        ensure!(expected == reference, "content task reference changed");
        let task = *task;
        let path = query.get("path").context("private path required")?;
        self.admitted(task, path, method != "GET")?;
        if method == "DELETE" {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Reply::json(true));
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
        }
        let mut file = self.open(task, path, method != "GET")?;
        let before = identity(&file)?;
        let reply = match method {
            "GET" => {
                let size = file.metadata()?.len();
                ensure!(
                    size <= i64::MAX as u64,
                    unavailable("private file too large")
                );
                if query.get("metadata").is_some_and(|v| v == "true") {
                    Reply::json(FileInfo {
                        name: Path::new(path)
                            .file_name()
                            .context("file name required")?
                            .to_string_lossy()
                            .into_owned(),
                        description: String::new(),
                        is_directory: false,
                        is_hidden: true,
                        path: path.clone(),
                        mine_type: "application/octet-stream".into(),
                        size: size as i64,
                        created_date: 0,
                        updated_date: 0,
                        protocol: Protocol::Local,
                        protocol_id: String::new(),
                        is_ignored: false,
                        is_symbolic_link: false,
                        is_symbolic_link_known: false,
                        sensitivity: Sensitivity::None,
                        sensitivity_category: String::new(),
                        storage_reference: None,
                    })
                } else {
                    let offset = query
                        .get("offset")
                        .context("offset required")?
                        .parse::<i64>()?;
                    let length = query
                        .get("length")
                        .context("length required")?
                        .parse::<i64>()?;
                    ensure!(
                        offset >= 0
                            && (offset as u64) <= size
                            && (0..=crate::management::wire::BODY_LIMIT as i64).contains(&length)
                            && (length as u64) <= size - offset as u64,
                        "invalid private file range"
                    );
                    let mut bytes = vec![0u8; length as usize];
                    file.seek(SeekFrom::Start(offset as u64))?;
                    file.read_exact(&mut bytes)
                        .map_err(|_| unavailable("private staging source changed"))?;
                    Reply::bytes(bytes)
                }
            }
            "PUT" => {
                let size = query.get("size").context("size required")?.parse::<i64>()?;
                let offset = query
                    .get("offset")
                    .context("offset required")?
                    .parse::<i64>()?;
                ensure!(
                    size >= 0
                        && offset >= 0
                        && offset <= size
                        && (body.len() as u64) <= (size - offset) as u64,
                    "invalid private write range"
                );
                file.set_len(size as u64)?;
                file.seek(SeekFrom::Start(offset as u64))?;
                file.write_all(body)?;
                Reply::json(true)
            }
            "DELETE" => {
                let (parent, name, _) = files::open_parent_nofollow(Path::new(path))?;
                parent.remove_file(name)?;
                return Ok(Reply::json(true));
            }
            _ => anyhow::bail!("unsupported private file method"),
        };
        ensure!(
            self.identity(task, path)? == before,
            unavailable("private staging ownership changed")
        );
        Ok(reply)
    }
}

pub(super) fn publish_private(
    source: &mut std::fs::File,
    destination: &Path,
    decrypt: Option<(Zeroizing<[u8; 32]>, String)>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<()> {
    let (parent, name, absolute) = files::open_parent_nofollow(destination)?;
    match parent.symlink_metadata(&name) {
        Ok(meta) => ensure!(
            meta.is_file() && !meta.is_symlink(),
            unavailable("content destination is not an ordinary file")
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = PathBuf::from(format!(".folderspan-publish-{}.part", new_uuid()?));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let mut output = parent.open_with(&temporary, &options)?.into_std();
    let result = (|| -> Result<()> {
        let path = absolute
            .parent()
            .context("content destination parent missing")?
            .join(&temporary);
        config::restrict_private(&path, false)?;
        let check = || -> Result<()> {
            ensure!(
                !cancel.is_cancelled(),
                unavailable("content operation cancelled")
            );
            Ok(())
        };
        if let Some((key, scope)) = decrypt {
            crate::storage::content_crypto::decrypt(
                source,
                &mut output,
                &key,
                &scope,
                &mut || check(),
            )?;
        } else {
            let mut bytes = Zeroizing::new(vec![0; 64 * 1024]);
            loop {
                check()?;
                let n = source.read(&mut bytes)?;
                if n == 0 {
                    break;
                }
                output.write_all(&bytes[..n])?;
            }
        }
        output.sync_all()?;
        check()?;
        ensure!(
            files::file_identity(&output)
                == files::file_identity(
                    &parent
                        .open_with(
                            &temporary,
                            OpenOptions::new().read(true).follow(FollowSymlinks::No)
                        )?
                        .into_std()
                ),
            unavailable("private publication ownership changed")
        );
        parent.rename(&temporary, &parent, &name)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = parent.remove_file(temporary);
    }
    result
}
