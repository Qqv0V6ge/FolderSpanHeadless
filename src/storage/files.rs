use crate::management::{reply::Reply, session::Session, wire::BODY_LIMIT};
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, Metadata, OpenOptions, ReadDir},
};
use serde_json::{Value, json};
use std::{
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

#[cfg(windows)]
mod windows;

pub struct FilePolicy {
    pub private: Vec<PathBuf>,
}
struct Directory {
    entries: ReadDir,
    path: PathBuf,
    count: bool,
}
fn denied() -> anyhow::Error {
    std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()
}
pub(crate) fn within(path: &Path, root: &Path) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        let p = path.to_string_lossy().to_lowercase();
        let r = root.to_string_lossy().to_lowercase();
        p == r || p.starts_with(&(r + std::path::MAIN_SEPARATOR_STR))
    } else {
        path.starts_with(root)
    }
}
pub(crate) fn open_parent_nofollow(path: &Path) -> Result<(Dir, PathBuf, PathBuf)> {
    let absolute = std::path::absolute(path)?;
    let root = absolute.ancestors().last().context("no path root")?;
    let mut dir = Dir::open_ambient_dir(root, ambient_authority())?;
    let parent = absolute.parent().unwrap_or(root);
    for c in parent.strip_prefix(root)?.components() {
        match c {
            Component::Normal(n) => dir = dir.open_dir_nofollow(n)?,
            Component::CurDir => {}
            _ => return Err(denied()),
        }
    }
    let name = absolute
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((dir, name, absolute))
}
impl FilePolicy {
    pub fn check(&self, path: &Path, session: &Session) -> Result<()> {
        if path.as_os_str().is_empty() {
            return Err(denied());
        }
        let path = std::path::absolute(path)?;
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(denied());
        }
        let own = within(&path, &session.cache);
        if self.private.iter().any(|r| within(&path, r)) && !own {
            return Err(denied());
        }
        #[cfg(unix)]
        if ["/dev", "/proc", "/sys"]
            .iter()
            .any(|p| path.starts_with(p))
        {
            return Err(denied());
        }
        #[cfg(windows)]
        {
            let raw = path.to_string_lossy();
            if raw.starts_with("\\\\")
                || raw.contains(':') && raw[2..].contains(':')
                || path
                    .components()
                    .filter_map(|c| {
                        if let Component::Normal(n) = c {
                            n.to_str()
                        } else {
                            None
                        }
                    })
                    .any(|s| {
                        s.ends_with([' ', '.'])
                            || matches!(
                                s.split('.')
                                    .next()
                                    .unwrap_or("")
                                    .to_ascii_uppercase()
                                    .as_str(),
                                "CON"
                                    | "PRN"
                                    | "AUX"
                                    | "NUL"
                                    | "COM1"
                                    | "COM2"
                                    | "COM3"
                                    | "COM4"
                                    | "LPT1"
                                    | "LPT2"
                                    | "LPT3"
                            )
                    })
            {
                return Err(denied());
            }
        }
        Ok(())
    }
    fn check_tree_mutation(&self, path: &Path, session: &Session) -> Result<()> {
        self.check(path, session)?;
        let path = std::path::absolute(path)?;
        // Moving/deleting an ancestor must not relocate or erase private application state.
        if self.private.iter().any(|private| within(private, &path)) {
            return Err(denied());
        }
        Ok(())
    }
    fn parent(&self, path: &Path, session: &Session) -> Result<(Dir, PathBuf, PathBuf)> {
        self.check(path, session)?;
        open_parent_nofollow(path)
    }
    fn directory(&self, path: &Path, session: &Session) -> Result<Dir> {
        let (parent, name, _) = self.parent(path, session)?;
        Ok(parent.open_dir_nofollow(name)?)
    }
    pub(crate) fn make_directory(&self, path: &Path, session: &Session) -> Result<()> {
        self.check(path, session)?;
        let absolute = std::path::absolute(path)?;
        let root = absolute.ancestors().last().context("no path root")?;
        let mut dir = Dir::open_ambient_dir(root, ambient_authority())?;
        for part in absolute.strip_prefix(root)?.components() {
            match part {
                Component::Normal(name) => {
                    dir = match dir.open_dir_nofollow(name) {
                        Ok(child) => child,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            match dir.create_dir(name) {
                                Ok(()) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                                Err(e) => return Err(e.into()),
                            }
                            dir.open_dir_nofollow(name)?
                        }
                        Err(error) => return Err(error.into()),
                    };
                }
                Component::CurDir => {}
                _ => return Err(denied()),
            }
        }
        Ok(())
    }
    pub(crate) fn receive_target(&self, path: &Path, session: &Session) -> Result<ReceiveTarget> {
        self.check(path, session)?;
        self.make_directory(path.parent().context("no file parent")?, session)?;
        let (parent, name, _) = self.parent(path, session)?;
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
        match parent.open_with(&name, &options) {
            Ok(file) => Ok(ReceiveTarget {
                file: file.into_std(),
                cleanup: Some((parent, name)),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(ReceiveTarget {
                file: self.open(path, session, true, false, false)?.into_std(),
                cleanup: None,
            }),
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) fn open(
        &self,
        path: &Path,
        session: &Session,
        write: bool,
        create: bool,
        append: bool,
    ) -> Result<cap_std::fs::File> {
        let (parent, name, _) = self.parent(path, session)?;
        let mut opt = OpenOptions::new();
        opt.read(!append)
            .write(write)
            .create(create)
            .append(append)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            opt.custom_flags(libc::O_NONBLOCK);
        }
        let file = parent.open_with(name, &opt)?;
        ensure!(file.metadata()?.is_file(), "not an ordinary file");
        Ok(file)
    }
    fn info(&self, path: &Path, session: &Session, details: bool) -> Result<Value> {
        let (parent, name, path) = self.parent(path, session)?;
        let meta = parent.symlink_metadata(&name)?;
        ensure!(
            !meta.is_symlink() && (meta.is_dir() || meta.is_file()),
            "not an ordinary file"
        );
        let mut value = self.entry(&path, &meta, !details, session);
        if details {
            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                use nix::unistd::{Gid, Group, Uid, User};
                let uid = meta.uid();
                let gid = meta.gid();
                value["permissions"] = json!(meta.mode() & 0o777);
                value["user"] = json!(
                    User::from_uid(Uid::from_raw(uid))
                        .ok()
                        .flatten()
                        .map_or_else(|| uid.to_string(), |user| user.name)
                );
                value["userGroup"] = json!(
                    Group::from_gid(Gid::from_raw(gid))
                        .ok()
                        .flatten()
                        .map_or_else(|| gid.to_string(), |group| group.name)
                );
            }
            #[cfg(windows)]
            {
                value["permissions"] = json!(0);
                value["user"] = json!(windows::owner(&parent, &name).unwrap_or_default());
                value["userGroup"] = json!("");
            }
        }
        Ok(value)
    }
    fn entry(&self, path: &Path, m: &Metadata, count: bool, session: &Session) -> Value {
        let protected = self.check(path, session).is_err();
        let size = match (m.is_dir(), count, protected) {
            (true, true, false) => self
                .directory(path, session)
                .and_then(|dir| {
                    let mut count = 0;
                    for entry in dir.entries()? {
                        ensure!(!session.cancel.is_cancelled(), "session closed");
                        entry?;
                        count += 1;
                    }
                    Ok(count)
                })
                .unwrap_or(0),
            (true, true, true) => 0,
            (true, false, _) => -1,
            (false, _, _) => m.len() as i64,
        };
        let millis = |v: std::io::Result<cap_std::time::SystemTime>| {
            v.ok()
                .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
                .map(|t| t.as_millis() as u64)
                .unwrap_or(0)
        };
        let name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy();
        let extension = if m.is_file() {
            name.rsplit_once('.')
                .filter(|(_, suffix)| !suffix.is_empty())
                .map(|(_, suffix)| format!(".{}", suffix.to_lowercase()))
                .unwrap_or_default()
        } else {
            String::new()
        };
        json!({"name":name,"description":"","isDirectory":m.is_dir(),"isHidden":name.starts_with('.'),"path":path,
            "mineType":extension,
            "size":size,"createdDate":millis(m.created()),"updatedDate":millis(m.modified()),
            "protocol":"Local","protocolId":"","isIgnored":false,"isSymbolicLink":m.is_symlink(),"isSymbolicLinkKnown":true,
            "sensitivity":if protected{"critical"}else{"none"},"sensitivityCategory":if protected{"application_private_data"}else{""},"storageReference":null})
    }
    pub fn handle(&self, method: &str, raw: &str, body: &[u8], session: &Session) -> Result<Reply> {
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let q = crate::management::wire::query(query);
        let query = |k: &str| {
            q.get(k)
                .map(String::as_str)
                .context("missing query parameter")
        };
        let number = |k: &str| -> Result<u64> { Ok(query(k)?.parse()?) };
        let operation = path
            .strip_prefix("/api/web-ui/platform")
            .context("invalid platform path")?;
        let input = || -> Result<Value> { Ok(serde_json::from_slice(body)?) };
        let p = || query("path").map(Path::new);
        match (method, operation) {
            ("GET", "/files/info") => Ok(Reply::json(self.info(p()?, session, false)?)),
            ("GET", "/files/details") => Ok(Reply::json(self.info(p()?, session, true)?)),
            ("GET", "/files/roots") => Ok(Reply::json(roots())),
            ("GET", "/files/space") => {
                self.check(p()?, session)?;
                #[cfg(target_os = "macos")]
                let space = [-1i64, -1i64];
                #[cfg(not(target_os = "macos"))]
                let space = [
                    fs2::total_space(p()?)? as i64,
                    fs2::available_space(p()?)? as i64,
                ];
                Ok(Reply::json(space))
            }
            ("GET", "/files/exists") | ("GET", "/files/symlink") => {
                let result = self
                    .parent(p()?, session)
                    .and_then(|(dir, name, _)| Ok(dir.symlink_metadata(name)?));
                let value = match result {
                    Ok(m) => {
                        if operation.ends_with("symlink") {
                            m.is_symlink()
                        } else {
                            true
                        }
                    }
                    Err(e)
                        if e.downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        false
                    }
                    Err(e) => return Err(e),
                };
                Ok(Reply::json(value))
            }
            ("GET", "/files/directory-writable") => {
                let (parent, name, _) = self.parent(p()?, session)?;
                let meta = parent.symlink_metadata(&name)?;
                if meta.is_file() {
                    return Ok(Reply::json(false));
                }
                ensure!(meta.is_dir() && !meta.is_symlink(), denied());
                let dir = parent.open_dir_nofollow(name)?;
                let name = format!(
                    ".folderspan-write-probe-{}",
                    crate::runtime::config::random_id(8)
                );
                let mut opt = OpenOptions::new();
                opt.write(true).create_new(true).follow(FollowSymlinks::No);
                let writable = match dir.open_with(&name, &opt) {
                    Ok(f) => {
                        drop(f);
                        dir.remove_file(name)?;
                        true
                    }
                    Err(_) => false,
                };
                Ok(Reply::json(writable))
            }
            ("GET", "/files/canonical") => {
                let path = p()?;
                self.check(path, session)?;
                let path = std::path::absolute(path)?;
                let resolved = if path.exists() {
                    crate::runtime::config::canonical_path(&path)?
                } else if q.get("allowMissing").is_some_and(|x| x == "true") {
                    let parent = path.parent().context("no parent")?;
                    let parent = match crate::runtime::config::canonical_path(parent) {
                        Ok(parent) => parent,
                        Err(e)
                            if e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                matches!(io.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
                            }) =>
                        {
                            return Ok(Reply::json(Value::Null));
                        }
                        Err(e) => return Err(e),
                    };
                    parent.join(path.file_name().context("no leaf")?)
                } else {
                    return Ok(Reply::json(Value::Null));
                };
                self.check(&resolved, session)?;
                Ok(Reply::json(resolved))
            }
            ("POST", "/files/boundary") => {
                let v = input()?;
                let root = Path::new(string(&v, "root")?);
                let target = Path::new(string(&v, "path")?);
                self.check(root, session)?;
                self.check(target, session)?;
                let allowed = (|| -> Result<bool> {
                    let (dir, name, absolute) = self.parent(target, session)?;
                    let root = std::path::absolute(root)?;
                    if !within(&absolute, &root) {
                        return Ok(false);
                    }
                    if within(&root, &absolute)
                        && dir
                            .symlink_metadata(&name)
                            .is_ok_and(|metadata| metadata.is_file() && !metadata.is_symlink())
                    {
                        return Ok(true);
                    }
                    self.directory(&root, session)?;
                    match dir.symlink_metadata(name) {
                        Ok(m) => Ok(!m.is_symlink()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            Ok(v["allowMissing"] == true)
                        }
                        Err(e) => Err(e.into()),
                    }
                })()
                .unwrap_or(false);
                Ok(Reply::json(allowed))
            }
            ("POST", "/files/directories") => {
                let v = input()?;
                let path = Path::new(string(&v, "path")?);
                let d = self.directory(path, session)?;
                let count = match q.get("includeDirectoryEntryCount").map(String::as_str) {
                    None | Some("true") => true,
                    Some("false") => false,
                    Some(_) => anyhow::bail!("invalid directory entry count option"),
                };
                let id = session.own(Mutex::new(Directory {
                    entries: d.entries()?,
                    path: std::path::absolute(path)?,
                    count,
                }))?;
                Ok(Reply::json(json!({"id":id})))
            }
            ("GET", "/files/directories") => {
                let id = query("handle")?;
                let resource = session.resource::<Mutex<Directory>>(id)?;
                let mut d = resource.lock().unwrap();
                let mut entries = vec![];
                let mut issues = vec![];
                let mut finished = false;
                for _ in 0..128 {
                    if session.cancel.is_cancelled() {
                        anyhow::bail!("session closed");
                    }
                    match d.entries.next() {
                        None => {
                            finished = true;
                            break;
                        }
                        Some(Err(_)) => issues.push("directory entry failed".to_string()),
                        Some(Ok(e)) => {
                            let name = e.file_name();
                            if name.to_str().is_none() {
                                issues.push("directory entry name is not valid UTF-8".to_string());
                                continue;
                            }
                            let path = d.path.join(name);
                            match e.metadata() {
                                Ok(m) => entries.push(self.entry(&path, &m, d.count, session)),
                                Err(_) => issues.push("directory entry failed".to_string()),
                            }
                        }
                    }
                }
                drop(d);
                if finished {
                    session.release(id);
                }
                Ok(Reply::json(
                    json!({"entries":entries,"finished":finished,"issues":issues}),
                ))
            }
            ("POST", "/files/create") | ("POST", "/files/mkdir") | ("POST", "/files/mkdirs") => {
                let v = input()?;
                let path = Path::new(string(&v, "path")?);
                if operation == "/files/mkdirs" {
                    let existing = self
                        .parent(path, session)
                        .and_then(|(dir, name, _)| Ok(dir.symlink_metadata(name)?));
                    match existing {
                        Ok(meta) => ensure!(meta.is_dir() || meta.is_file(), denied()),
                        Err(e)
                            if e.downcast_ref::<std::io::Error>()
                                .is_some_and(|io| io.kind() == ErrorKind::NotFound) =>
                        {
                            self.make_directory(path, session)?;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    let (dir, name, _) = self.parent(path, session)?;
                    if operation == "/files/mkdir" {
                        dir.create_dir(name)?;
                    } else {
                        let mut o = OpenOptions::new();
                        o.write(true).create_new(true).follow(FollowSymlinks::No);
                        dir.open_with(name, &o)?;
                    }
                }
                Ok(Reply::json(true))
            }
            ("POST", "/files/append") => {
                ensure!(body.len() <= BODY_LIMIT, "body too large");
                let mut f = self.open(p()?, session, true, true, true)?;
                f.write_all(body)?;
                Ok(Reply::json(true))
            }
            ("GET", "/files/content") => {
                let mut f = self.open(p()?, session, false, false, false)?;
                let size = f.metadata()?.len();
                let offset = q
                    .get("offset")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let length = q
                    .get("length")
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(BODY_LIMIT as i32);
                ensure!(
                    offset >= 0 && (1..=BODY_LIMIT as i32).contains(&length),
                    "invalid file range"
                );
                let offset = offset as u64;
                let length = length as usize;
                ensure!(offset <= size, "invalid file range");
                let mut b = vec![0; length.min((size - offset) as usize)];
                f.seek(SeekFrom::Start(offset))?;
                f.read_exact(&mut b)?;
                let range = if b.is_empty() {
                    format!("bytes */{size}")
                } else {
                    format!("bytes {offset}-{}/{size}", offset + b.len() as u64 - 1)
                };
                let mut r = Reply::bytes(b);
                r.headers.insert("accept-ranges".into(), "bytes".into());
                r.headers.insert("content-range".into(), range);
                Ok(r)
            }
            ("PUT", "/files/content") => {
                let size = number("size")?;
                let offset = number("offset")?;
                ensure!(
                    body.len() <= BODY_LIMIT
                        && offset <= size
                        && body.len() as u64 <= size - offset,
                    "invalid write range"
                );
                let mut f = self.open(p()?, session, true, true, false)?;
                f.set_len(size)?;
                f.seek(SeekFrom::Start(offset))?;
                f.write_all(body)?;
                Ok(Reply::json(true))
            }
            ("POST", "/files/set-modified-time") => {
                let v = input()?;
                let path = Path::new(string(&v, "path")?);
                let millis = v["millis"]
                    .as_u64()
                    .filter(|&ms| ms > 0 && ms <= i64::MAX as u64)
                    .context("invalid modification time")?;
                let time = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_millis(millis))
                    .context("invalid modification time")?;
                let (parent, name, _) = self.parent(path, session)?;
                let meta = parent.symlink_metadata(&name)?;
                ensure!(meta.is_file() || meta.is_dir(), denied());
                #[cfg(unix)]
                // Update attributes without opening the file for data writes or following a replacement link.
                parent.set_symlink_times(
                    &name,
                    None,
                    Some(cap_fs_ext::SystemTimeSpec::Absolute(
                        cap_std::time::SystemTime::from_std(time),
                    )),
                )?;
                #[cfg(windows)]
                windows::set_modified(&parent, &name, time)?;
                Ok(Reply::json(true))
            }
            ("POST", "/files/move") | ("POST", "/files/rename") => {
                let v = input()?;
                let (from, to) = if operation.ends_with("rename") {
                    let parent = Path::new(string(&v, "path")?);
                    let old = string(&v, "oldName")?;
                    let new = string(&v, "newName")?;
                    leaf(old)?;
                    leaf(new)?;
                    (parent.join(old), parent.join(new))
                } else {
                    (
                        PathBuf::from(string(&v, "from")?),
                        PathBuf::from(string(&v, "to")?),
                    )
                };
                self.check_tree_mutation(&from, session)?;
                let (src, name, _) = self.parent(&from, session)?;
                let (dst, new, _) = self.parent(&to, session)?;
                let meta = src.symlink_metadata(&name)?;
                ensure!(
                    !meta.is_symlink() && (meta.is_file() || meta.is_dir()),
                    "invalid move source"
                );
                rename_no_replace(&src, &name, &dst, &new)?;
                Ok(Reply::json(true))
            }
            ("DELETE", "/files")
            | ("POST", "/files/delete-empty-directory")
            | ("DELETE", "/files/tree") => {
                let path = if method == "POST" {
                    PathBuf::from(string(&input()?, "path")?)
                } else {
                    p()?.to_path_buf()
                };
                ensure!(
                    path.parent().is_some() && path.file_name().is_some(),
                    "cannot delete filesystem root"
                );
                self.check_tree_mutation(&path, session)?;
                let (dir, name, _) = self.parent(&path, session)?;
                let m = dir.symlink_metadata(&name)?;
                ensure!(
                    !m.is_symlink() && (m.is_dir() || m.is_file()),
                    "invalid delete target"
                );
                if m.is_dir() {
                    if operation == "/files/tree" {
                        remove_tree(&dir, &name, session)?;
                    } else {
                        dir.remove_dir(name)?;
                    }
                } else {
                    ensure!(
                        operation != "/files/delete-empty-directory",
                        "not a directory"
                    );
                    dir.remove_file(name)?;
                }
                Ok(Reply::json(true))
            }
            ("DELETE", "/resources") => {
                session.release(query("handle")?);
                Ok(Reply::json(true))
            }
            _ => Ok(Reply::error(404, "not_found", "unknown platform operation")),
        }
    }
}
pub fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().context("missing string field")
}
fn leaf(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && !matches!(name, "." | "..") && !name.contains(['/', '\\', '\0']),
        "invalid file name"
    );
    Ok(())
}
fn remove_tree(parent: &Dir, name: &Path, session: &Session) -> Result<()> {
    let dir = parent.open_dir_nofollow(name)?;
    for e in dir.entries()? {
        ensure!(!session.cancel.is_cancelled(), "session closed");
        let e = e?;
        let n = PathBuf::from(e.file_name());
        let meta = dir.symlink_metadata(&n)?;
        if meta.is_dir() && !meta.is_symlink() {
            remove_tree(&dir, &n, session)?;
        } else {
            dir.remove_file_or_symlink(&n)?;
        }
    }
    parent.remove_dir(name)?;
    Ok(())
}
fn rename_no_replace(src: &Dir, name: &Path, dst: &Dir, new: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
        let name = CString::new(name.as_os_str().as_bytes())?;
        let new = CString::new(new.as_os_str().as_bytes())?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                src.as_raw_fd(),
                name.as_ptr(),
                dst.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                src.as_raw_fd(),
                name.as_ptr(),
                dst.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use cap_std::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
            SYNCHRONIZE,
        };
        use windows_sys::{
            Wdk::Storage::FileSystem::{
                FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
            },
            Win32::{
                Foundation::{RtlNtStatusToDosError, STATUS_PENDING, WAIT_OBJECT_0},
                System::{
                    IO::IO_STATUS_BLOCK,
                    Threading::{INFINITE, WaitForSingleObject},
                },
            },
        };
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .follow(FollowSymlinks::No);
        let file = src.open_with(name, &options)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "invalid move source"
        );
        let target = new.as_os_str().encode_wide().collect::<Vec<_>>();
        let name_bytes = target
            .len()
            .checked_mul(2)
            .context("rename name exceeds limit")?;
        let bytes = std::mem::size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(name_bytes)
            .context("rename buffer exceeds limit")?;
        let length = u32::try_from(bytes)?;
        // u64 storage preserves native structure alignment on both x64 and arm64.
        let mut storage = vec![0u64; bytes.div_ceil(8)];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut completion: Box<IO_STATUS_BLOCK> = Box::new(unsafe { std::mem::zeroed() });
        // NtSetInformationFile honors the destination directory handle on Windows 10 too.
        let status = unsafe {
            (*info).Anonymous.ReplaceIfExists = 0;
            (*info).RootDirectory = dst.as_raw_handle().cast();
            (*info).FileNameLength = u32::try_from(name_bytes)?;
            std::ptr::copy_nonoverlapping(
                target.as_ptr(),
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName))
                    .cast::<u16>(),
                target.len(),
            );
            NtSetInformationFile(
                file.as_raw_handle().cast(),
                &mut *completion,
                info.cast(),
                length,
                FileRenameInformation,
            )
        };
        let status = if status == STATUS_PENDING {
            if unsafe { WaitForSingleObject(file.as_raw_handle().cast(), INFINITE) }
                != WAIT_OBJECT_0
            {
                // Keep pending kernel I/O buffers alive if completion cannot be observed.
                Box::leak(completion);
                std::mem::forget(storage);
                return Err(crate::management::reply::ResourceUnavailable(
                    "rename completion could not be confirmed",
                )
                .into());
            }
            unsafe { completion.Anonymous.Status }
        } else {
            status
        };
        if status < 0 {
            return Err(std::io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            )
            .into());
        }
        Ok(())
    }
}
pub fn roots() -> Value {
    #[cfg(unix)]
    {
        json!([{"path":"/","totalSpace":if cfg!(target_os="macos"){0}else{fs2::total_space("/").unwrap_or(0)},"freeSpace":if cfg!(target_os="macos"){0}else{fs2::available_space("/").unwrap_or(0)}}])
    }
    #[cfg(windows)]
    {
        json!(
            (b'A'..=b'Z')
                .filter_map(|c| {
                    let p = format!("{}:\\", c as char);
                    Path::new(&p)
                        .is_dir()
                        .then(|| json!({"path":p,"totalSpace":0,"freeSpace":0}))
                })
                .collect::<Vec<_>>()
        )
    }
}

pub(crate) struct ReceiveTarget {
    pub file: std::fs::File,
    cleanup: Option<(Dir, PathBuf)>,
}
impl ReceiveTarget {
    pub fn commit(&mut self) {
        self.cleanup = None;
    }
}
pub(crate) fn file_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().ok()?;
        Some((m.dev(), m.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
            return None;
        }
        Some((
            info.dwVolumeSerialNumber as u64,
            ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        ))
    }
}
impl Drop for ReceiveTarget {
    fn drop(&mut self) {
        if let Some((parent, name)) = &self.cleanup {
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK);
            }
            if let Ok(current) = parent.open_with(name, &options) {
                let a = file_identity(&self.file);
                let b = file_identity(&current.into_std());
                if a.is_some() && a == b {
                    let _ = parent.remove_file(name);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_range_conflict_and_session_boundary() {
        let temp = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let private = temp.path().join("private");
        std::fs::create_dir(&private).unwrap();
        let s = Session::new(&private).unwrap();
        let other = Session::new(&private).unwrap();
        let p = FilePolicy {
            private: vec![private.clone()],
        };
        let f = temp.path().join("你好 .txt");
        let q = format!(
            "/api/web-ui/platform/files/content?path={}&size=5&offset=0",
            url::form_urlencoded::byte_serialize(f.to_str().unwrap().as_bytes())
                .collect::<String>()
        );
        p.handle("PUT", &q, b"abcde", &s).unwrap();
        let read = q.replace("&size=5&offset=0", "&offset=2&length=2");
        assert_eq!(p.handle("GET", &read, &[], &s).unwrap().body, b"cd");
        assert!(
            p.handle("PUT", &q.replace("offset=0", "offset=4"), b"xx", &s)
                .is_err()
        );
        assert_eq!(std::fs::read(&f).unwrap(), b"abcde");
        assert!(p.check(&other.cache, &s).is_err());
        assert!(p.check(&s.cache, &s).is_ok());
        let body = serde_json::to_vec(&json!({"path":f})).unwrap();
        assert!(
            p.handle("POST", "/api/web-ui/platform/files/create", &body, &s)
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_parent_and_never_overwrites() {
        let temp = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let s = Session::new(temp.path()).unwrap();
        let p = FilePolicy { private: vec![] };
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let body = serde_json::to_vec(&json!({"from":a,"to":b})).unwrap();
        assert!(
            p.handle("POST", "/api/web-ui/platform/files/move", &body, &s)
                .is_err()
        );
        assert_eq!(std::fs::read(&b).unwrap(), b"b");
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(temp.path(), &link).unwrap();
        assert!(p.open(&link.join("a"), &s, false, false, false).is_err());
        assert!(
            p.open(&link.join("..").join("a"), &s, false, false, false)
                .is_err()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_ranges_above_four_gib_preserve_u64_offsets() {
        let temp = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let session = Session::new(temp.path()).unwrap();
        let policy = FilePolicy { private: vec![] };
        let file = temp.path().join("sparse.bin");
        let offset = 5u64 * 1024 * 1024 * 1024;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("path", file.to_str().unwrap())
            .append_pair("size", &(offset + 1).to_string())
            .append_pair("offset", &offset.to_string())
            .finish();
        policy
            .handle(
                "PUT",
                &format!("/api/web-ui/platform/files/content?{query}"),
                b"Z",
                &session,
            )
            .unwrap();
        assert_eq!(std::fs::metadata(&file).unwrap().len(), offset + 1);
        let reply = policy
            .handle(
                "GET",
                &format!("/api/web-ui/platform/files/content?{query}&length=1"),
                &[],
                &session,
            )
            .unwrap();
        assert_eq!(reply.body, b"Z");
    }
    #[test]
    fn ancestor_mutations_cannot_erase_or_relocate_private_state() {
        let temp = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let container = temp.path().join("container");
        let private = container.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("credential"), b"secret").unwrap();
        let session = Session::new(&private).unwrap();
        let policy = FilePolicy {
            private: vec![private.clone()],
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("path", container.to_str().unwrap())
            .finish();
        assert!(
            policy
                .handle(
                    "DELETE",
                    &format!("/api/web-ui/platform/files/tree?{query}"),
                    &[],
                    &session
                )
                .is_err()
        );
        let body =
            serde_json::to_vec(&json!({"from":container,"to":temp.path().join("relocated")}))
                .unwrap();
        assert!(
            policy
                .handle("POST", "/api/web-ui/platform/files/move", &body, &session)
                .is_err()
        );
        assert_eq!(
            std::fs::read(private.join("credential")).unwrap(),
            b"secret"
        );
    }
    #[cfg(unix)]
    #[test]
    fn non_utf8_directory_entries_report_an_issue_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let listing = temp.path().join("listing");
        std::fs::create_dir(&listing).unwrap();
        let created = std::fs::write(listing.join(std::ffi::OsString::from_vec(vec![255])), b"x");
        #[cfg(target_os = "macos")]
        if created
            .as_ref()
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(libc::EILSEQ))
        {
            // APFS rejects this fixture before the directory iterator can observe it.
            assert_eq!(std::fs::read_dir(&listing).unwrap().count(), 0);
            return;
        }
        created.unwrap();
        let session = Session::new(temp.path()).unwrap();
        let policy = FilePolicy { private: vec![] };
        let opened = policy
            .handle(
                "POST",
                "/api/web-ui/platform/files/directories",
                &serde_json::to_vec(&json!({"path":listing})).unwrap(),
                &session,
            )
            .unwrap();
        let opened: Value = serde_json::from_slice(&opened.body).unwrap();
        let batch = policy
            .handle(
                "GET",
                &format!(
                    "/api/web-ui/platform/files/directories?handle={}",
                    opened["id"].as_str().unwrap()
                ),
                &[],
                &session,
            )
            .unwrap();
        let batch: Value = serde_json::from_slice(&batch.body).unwrap();
        assert_eq!(batch["entries"], json!([]));
        assert_eq!(batch["issues"].as_array().unwrap().len(), 1);
    }
}
