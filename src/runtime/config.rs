#[cfg(windows)]
mod windows;

use anyhow::{Context, Result, bail};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

pub const DISPLAY_NAME: &str = "FolderSpanHeadless";

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub settings: Settings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub web_root: PathBuf,
    pub bind_address: Option<IpAddr>,
    pub port: u16,
    pub allowed_origins: String,
}

#[derive(Clone, Debug)]
pub struct Launch {
    pub data_dir: PathBuf,
    web_root: Option<PathBuf>,
    bind_address: Option<IpAddr>,
    port: Option<u16>,
    allowed_origins: Option<String>,
}

impl Launch {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>> {
        let mut data_dir = None;
        let mut web_root = None;
        let mut bind_address = None;
        let mut port = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--data-dir" => {
                    data_dir = Some(PathBuf::from(
                        args.next().context("--data-dir requires a path")?,
                    ));
                }
                "--web-root" => {
                    web_root = Some(PathBuf::from(
                        args.next().context("--web-root requires a path")?,
                    ));
                }
                "--bind-address" => {
                    bind_address = Some(
                        args.next()
                            .context("--bind-address requires an IP address")?
                            .parse()
                            .context("invalid bind address")?,
                    )
                }
                "--port" => {
                    port = Some(
                        args.next()
                            .context("--port requires a number")?
                            .parse()
                            .context("invalid port")?,
                    );
                }
                "--help" | "-h" => {
                    println!(
                        "{DISPLAY_NAME}\nOpens the management terminal when launched interactively.\n  --data-dir PATH\n  --web-root PATH\n  --bind-address IP\n  --port PORT"
                    );
                    return Ok(None);
                }
                _ => bail!("unknown argument: {arg}"),
            }
        }
        let data_dir = match data_dir {
            Some(path) => path,
            None => dirs::data_local_dir()
                .context("cannot locate data directory")?
                .join("FolderSpanHeadlessRust"),
        };
        let allowed_origins = match std::env::var("FOLDERSPAN_WEB_UI_ALLOWED_ORIGINS") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => return Err(e).context("invalid FOLDERSPAN_WEB_UI_ALLOWED_ORIGINS"),
        };
        Ok(Some(Self {
            data_dir,
            web_root,
            bind_address,
            port,
            allowed_origins,
        }))
    }

    pub fn load_settings(&self) -> Result<(Settings, bool)> {
        match read_json(&self.data_dir.join("settings.json"))? {
            Some(settings) => Ok((settings, true)),
            None => Ok((Settings::defaults()?, false)),
        }
    }

    pub fn resolve(&self, mut settings: Settings) -> Config {
        if let Some(path) = &self.web_root {
            settings.web_root = path.clone();
        }
        if let Some(address) = self.bind_address {
            settings.bind_address = Some(address);
        }
        if let Some(port) = self.port {
            settings.port = port;
        }
        if let Some(origins) = &self.allowed_origins {
            settings.allowed_origins = origins.clone();
        }
        Config {
            data_dir: self.data_dir.clone(),
            settings,
        }
    }

    pub fn sources(&self, saved: bool) -> [&'static str; 4] {
        let base = if saved { "saved" } else { "default" };
        [
            if self.bind_address.is_some() {
                "argument"
            } else {
                base
            },
            if self.port.is_some() {
                "argument"
            } else {
                base
            },
            if self.web_root.is_some() {
                "argument"
            } else {
                base
            },
            if self.allowed_origins.is_some() {
                "environment"
            } else {
                base
            },
        ]
    }
}

impl Settings {
    fn defaults() -> Result<Self> {
        Ok(Self {
            web_root: std::env::current_exe()?
                .parent()
                .context("no executable directory")?
                .join("web-ui"),
            bind_address: None,
            port: 12043,
            allowed_origins: "*".into(),
        })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let mut settings = self.clone();
        anyhow::ensure!(
            !settings.web_root.as_os_str().is_empty(),
            "Web directory is empty"
        );
        settings.web_root = std::path::absolute(&settings.web_root)?;
        settings.policy([])?;
        let bytes = serde_json::to_vec(&settings)?;
        anyhow::ensure!(
            bytes.len() <= 64 * 1024,
            "deployment settings exceed size limit"
        );
        write_private(&dir.join("settings.json"), &bytes)
    }

    pub fn policy(
        &self,
        hosts: impl IntoIterator<Item = String>,
    ) -> Result<crate::security::SecurityPolicy> {
        crate::security::SecurityPolicy::new(
            hosts,
            self.allowed_origins
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        )
    }
}

pub(crate) fn read_state(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "invalid state file type"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 <= limit, "state file exceeds size limit");
    Ok(Some(bytes))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    read_state(path, 64 * 1024)?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid saved deployment settings"))
        })
        .transpose()
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
    fn saved_settings_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let launch = Launch {
            data_dir: dir.path().into(),
            bind_address: None,
            port: Some(9090),
            allowed_origins: Some(String::new()),
            web_root: None,
        };
        let (mut settings, saved) = launch.load_settings().unwrap();
        assert!(!saved);
        settings.port = 8080;
        settings.allowed_origins = "https://example.test".into();
        settings.save(dir.path()).unwrap();
        let (settings, saved) = launch.load_settings().unwrap();
        assert!(saved);
        assert_eq!(settings.port, 8080);
        let effective = launch.resolve(settings).settings;
        assert_eq!(effective.port, 9090);
        assert_eq!(effective.allowed_origins, "");
    }
}
