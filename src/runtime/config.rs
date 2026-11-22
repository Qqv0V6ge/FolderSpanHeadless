#[cfg(windows)]
mod windows;

use anyhow::{Context, Result, bail};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

pub const DISPLAY_NAME: &str = "FolderSpanHeadless";

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub web_root: PathBuf,
    pub bind_address: Option<IpAddr>,
    pub port: u16,
    pub reset_key: bool,
}
impl Config {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>> {
        let mut c = Self {
            data_dir: dirs::data_local_dir()
                .context("cannot locate data directory")?
                // Resolve existing keys, certificates, and settings after the project rename.
                .join("FolderSpanHeadlessRust"),
            web_root: std::env::current_exe()?
                .parent()
                .context("no executable directory")?
                .join("web-ui"),
            bind_address: None,
            port: 12043,
            reset_key: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--data-dir" => {
                    c.data_dir = PathBuf::from(args.next().context("--data-dir requires a path")?)
                }
                "--web-root" => {
                    c.web_root = PathBuf::from(args.next().context("--web-root requires a path")?)
                }
                "--bind-address" => {
                    c.bind_address = Some(
                        args.next()
                            .context("--bind-address requires an IP address")?
                            .parse()
                            .context("invalid bind address")?,
                    )
                }
                "--port" => {
                    c.port = args
                        .next()
                        .context("--port requires a number")?
                        .parse()
                        .context("invalid port")?
                }
                "--reset-web-ui-key" => c.reset_key = true,
                "--help" | "-h" => {
                    println!(
                        "{DISPLAY_NAME}\n  --data-dir PATH\n  --web-root PATH\n  --bind-address IP (default: all interfaces)\n  --port PORT (default: 12043)\n  --reset-web-ui-key"
                    );
                    return Ok(None);
                }
                _ => bail!("unknown argument: {arg}"),
            }
        }
        Ok(Some(c))
    }
}
pub fn random_id(bytes: usize) -> String {
    let mut v = vec![0; bytes];
    OsRng.fill_bytes(&mut v);
    hex::encode(v)
}
pub fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    restrict_private(path, true)
}
pub fn restrict_private(path: &Path, directory: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !meta.file_type().is_symlink()
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            },
        "private path type changed"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    windows::restrict(path, directory)?;
    Ok(())
}
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("{}.tmp", random_id(8)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut f = options.open(&temp)?;
        restrict_private(&temp, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        #[cfg(not(windows))]
        fs::rename(&temp, path)?;
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let src: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let dst: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    src.as_ptr(),
                    dst.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
pub struct Credentials {
    hash: [u8; 32],
}
impl Credentials {
    pub fn load(dir: &Path, reset: bool) -> Result<(Self, Option<String>)> {
        let path = dir.join("web-ui-key.sha256");
        if path.exists() && !reset {
            let bytes = fs::read(&path)?;
            return Ok((
                Self {
                    hash: bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid stored credential hash"))?,
                },
                None,
            ));
        }
        let key = format!("fwui_{}_{}", random_id(8), random_id(32));
        let hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        write_private(&path, &hash)?;
        Ok((Self { hash }, Some(key)))
    }
    pub fn matches(&self, secret: &str) -> bool {
        let secret = secret.trim();
        let actual: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        !secret.is_empty() && !secret.starts_with("fmcp_") && bool::from(self.hash.ct_eq(&actual))
    }
}
// Windows canonicalization adds a verbatim prefix; do not expose that device-alias syntax to Web paths.
pub fn canonical_path(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize()?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if let Some(Component::Prefix(prefix)) = path.components().next()
            && let Prefix::VerbatimDisk(drive) = prefix.kind()
        {
            let mut ordinary = PathBuf::from(format!("{}:\\", drive as char));
            for component in path.components().skip(1) {
                if let Component::Normal(name) = component {
                    ordinary.push(name);
                }
            }
            return Ok(ordinary);
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_paths_require_ordinary_types_and_owner_permissions() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        private_directory(&directory).unwrap();
        let path = directory.join("secret");
        write_private(&path, b"secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        assert!(restrict_private(&directory, false).is_err());
        assert!(restrict_private(&path, true).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let alias = root.path().join("alias");
            symlink(&path, &alias).unwrap();
            assert!(restrict_private(&alias, false).is_err());
        }
    }
    #[test]
    fn credential_survives_and_rotates() {
        let d = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        let (c, k) = Credentials::load(d.path(), false).unwrap();
        let k = k.unwrap();
        assert!(c.matches(&format!(" {k} ")));
        assert!(!c.matches("fmcp_bad"));
        let (same, none) = Credentials::load(d.path(), false).unwrap();
        assert!(none.is_none());
        assert!(same.matches(&k));
        let (new, k2) = Credentials::load(d.path(), true).unwrap();
        assert!(!new.matches(&k));
        assert!(new.matches(&k2.unwrap()));
    }
}
