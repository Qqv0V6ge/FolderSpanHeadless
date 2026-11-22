mod wire;

use crate::{
    management::{
        reply::{PlatformFailure, ResourceUnavailable},
        session::Session,
    },
    storage::remote::{DownloadPart, Entry, endpoint, safe_segment},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use hmac::{Hmac, Mac};
use russh::{
    client,
    keys::{
        self, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker},
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    net::Shutdown,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc};
use tokio_util::sync::CancellationToken;
use wire::{Error as SftpError, FileType, OpenFlags, RawSftpSession, Status, StatusCode};
use zeroize::{Zeroize, Zeroizing};
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Extras {
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    known_hosts: String,
}
impl Drop for Extras {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
struct Credentials {
    username: String,
    password: String,
    private_key: Zeroizing<String>,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Clone)]
pub struct Sftp {
    host: String,
    port: u16,
    credentials: Arc<Credentials>,
    known: Option<Arc<Vec<KnownPin>>>,
    session: Weak<Session>,
    callback: String,
}
struct Guard {
    socket: std::net::TcpStream,
    cancel: CancellationToken,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
struct Connection {
    raw: RawSftpSession,
    _ssh: client::Handle<Handler>,
    _guard: Guard,
    copy: bool,
}

struct KnownPin {
    patterns: HostPatterns,
    marker: Option<Marker>,
    public: keys::PublicKey,
    certificate: Option<Vec<u8>>,
}
impl KnownPin {
    fn parse(line: &str) -> Option<Self> {
        if let Some(Ok(entry)) = KnownHosts::new(line).next() {
            return Some(Self {
                patterns: entry.host_patterns().clone(),
                marker: entry.marker().cloned(),
                public: entry.public_key().clone(),
                certificate: None,
            });
        }
        let mut words = line.split_whitespace();
        let first = words.next()?;
        let (marker, patterns) = if first.starts_with('@') {
            (Some(first.parse::<Marker>().ok()?), words.next()?)
        } else {
            (None, first)
        };
        let algorithm = words.next()?;
        let value = words.next()?;
        let certificate = keys::Certificate::from_openssh(&format!("{algorithm} {value}")).ok()?;
        Some(Self {
            patterns: patterns.parse().ok()?,
            marker,
            public: keys::PublicKey::new(certificate.public_key().clone(), ""),
            certificate: Some(certificate.to_bytes().ok()?),
        })
    }
    fn matches(&self, key: &PublicKeyOrCertificate) -> Result<bool> {
        if self.public.key_data() != key.public_key().key_data() {
            return Ok(false);
        }
        Ok(match (&self.certificate, key.certificate()) {
            (None, None) => true,
            (Some(expected), Some(certificate)) => *expected == certificate.to_bytes()?,
            _ => false,
        })
    }
}
fn verify_certificate(certificate: &keys::Certificate, host: &str) -> Result<()> {
    ensure!(
        certificate.cert_type() == keys::ssh_key::certificate::CertType::Host,
        PlatformFailure
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformFailure)?
        .as_secs();
    ensure!(
        certificate.valid_after() <= now
            && now < certificate.valid_before()
            && certificate.critical_options().is_empty()
            && certificate
                .valid_principals()
                .iter()
                .any(|p| glob(p, host, false)),
        PlatformFailure
    );
    // Authority trust still requires the exact certificate pin or approval below.
    certificate
        .verify_signature()
        .map_err(|_| PlatformFailure)?;
    Ok(())
}
struct Handler {
    owner: Sftp,
    cancel: CancellationToken,
}
fn glob(pattern: &str, host: &str, ignore_case: bool) -> bool {
    let (p, h) = (
        pattern.chars().collect::<Vec<_>>(),
        host.chars().collect::<Vec<_>>(),
    );
    let (mut i, mut j, mut star, mut back) = (0, 0, None, 0);
    while j < h.len() {
        if i < p.len()
            && (p[i] == '?' || p[i] == h[j] || ignore_case && p[i].eq_ignore_ascii_case(&h[j]))
        {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            back = j;
        } else if let Some(at) = star {
            back += 1;
            j = back;
            i = at + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}
fn hosts_match(patterns: &HostPatterns, host: &str, port: u16) -> bool {
    match patterns {
        HostPatterns::HashedName { salt, hash } => {
            let target = if port == 22 {
                host.to_owned()
            } else {
                format!("[{host}]:{port}")
            };
            <Hmac<Sha1> as Mac>::new_from_slice(salt).is_ok_and(|mac| {
                mac.chain_update(target.as_bytes())
                    .verify_slice(hash)
                    .is_ok()
            })
        }
        HostPatterns::Patterns(patterns) => {
            let mut positive = false;
            for pattern in patterns {
                let (negated, pattern) = pattern
                    .strip_prefix('!')
                    .map(|p| (true, p))
                    .unwrap_or((false, pattern.as_str()));
                let matched = if let Some(bracketed) = pattern.strip_prefix('[') {
                    bracketed.rsplit_once("]:").is_some_and(|(name, p)| {
                        p.parse::<u16>().ok() == Some(port) && glob(name, host, true)
                    })
                } else {
                    port == 22 && glob(pattern, host, true)
                };
                if matched && negated {
                    return false;
                }
                positive |= matched;
            }
            positive
        }
    }
}
impl client::Handler for Handler {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        if let Some(certificate) = key.certificate() {
            verify_certificate(certificate, &self.owner.host)?;
        }
        if let Some(known) = &self.owner.known {
            let mut accepted = false;
            for entry in known
                .iter()
                .filter(|e| hosts_match(&e.patterns, &self.owner.host, self.owner.port))
            {
                if entry.public.key_data() == key.public_key().key_data()
                    && matches!(entry.marker, Some(Marker::Revoked))
                {
                    return Ok(false);
                }
                if entry.marker.is_none() && entry.matches(key)? {
                    accepted = true;
                }
            }
            return Ok(accepted);
        }
        let encoded = match key {
            PublicKeyOrCertificate::Certificate(c) => c.to_bytes()?,
            _ => key.public_key().to_bytes()?,
        };
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(encoded)));
        let session = self
            .owner
            .session
            .upgrade()
            .context(ResourceUnavailable("session closed"))?;
        let payload = serde_json::to_vec(
            &json!({"host":self.owner.host,"port":self.owner.port,"fingerprint":fingerprint}),
        )?;
        tokio::select! {
            _=self.cancel.cancelled()=>Err(ResourceUnavailable("SFTP connection closed").into()),
            reply=session.callback(&self.owner.callback,"sftp-host-key",payload)=>Ok(serde_json::from_slice::<bool>(&reply?)?),
        }
    }
}
fn protocol<T>(result: std::result::Result<T, SftpError>) -> Result<T> {
    result.map_err(|_| PlatformFailure.into())
}
fn status(result: std::result::Result<Status, SftpError>) -> Result<bool> {
    ensure!(
        protocol(result)?.status_code == StatusCode::Ok,
        PlatformFailure
    );
    Ok(true)
}
fn missing(error: &SftpError) -> bool {
    matches!(error,SftpError::Status(s) if s.status_code==StatusCode::NoSuchFile)
}
impl Sftp {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        extras: &Value,
        session: &Arc<Session>,
        callback: &str,
    ) -> Result<Self> {
        let (host, port) = endpoint(host, 22)?;
        let mut extras: Extras =
            serde_json::from_value(extras.get("sftp").cloned().unwrap_or(json!({})))?;
        let known = if extras.known_hosts.trim().is_empty() {
            None
        } else {
            let normalized = extras
                .known_hosts
                .lines()
                .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join("\n");
            let entries = normalized
                .lines()
                .filter_map(KnownPin::parse)
                .collect::<Vec<_>>();
            ensure!(
                !entries.is_empty(),
                "SFTP known_hosts contains no usable key"
            );
            Some(Arc::new(entries))
        };
        Ok(Self {
            host,
            port,
            credentials: Arc::new(Credentials {
                username: username.into(),
                password: password.into(),
                private_key: Zeroizing::new(std::mem::take(&mut extras.private_key)),
            }),
            known,
            session: Arc::downgrade(session),
            callback: callback.into(),
        })
    }
    fn normalize(path: &str) -> Result<String> {
        let path = if path.trim().is_empty() {
            "/".into()
        } else {
            path.replace('\\', "/")
        };
        let parts = path.trim_matches('/');
        ensure!(
            parts.is_empty() || parts.split('/').all(safe_segment),
            "invalid SFTP path"
        );
        Ok(path)
    }
    async fn connect(&self) -> Result<Connection> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let socket = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|_| PlatformFailure)?
                .into_std()?;
            let guard = Guard {
                socket: socket.try_clone()?,
                cancel: CancellationToken::new(),
            };
            let mut config = client::Config {
                window_size: 256 * 1024,
                maximum_packet_size: 64 * 1024,
                channel_buffer_size: 1,
                inactivity_timeout: Some(Duration::from_secs(300)),
                ..Default::default()
            };
            use keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
            config.preferred.host_key_certificates = std::borrow::Cow::Owned(vec![
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384,
                },
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP521,
                },
                Algorithm::Ed25519,
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
            ]);
            let mut ssh = client::connect_stream(
                Arc::new(config),
                TcpStream::from_std(socket)?,
                Handler {
                    owner: self.clone(),
                    cancel: guard.cancel.clone(),
                },
            )
            .await
            .map_err(|_| PlatformFailure)?;
            let authenticated = if self.credentials.private_key.trim().is_empty() {
                ssh.authenticate_password(
                    self.credentials.username.as_str(),
                    self.credentials.password.as_str(),
                )
                .await
                .map_err(|_| PlatformFailure)?
            } else {
                let credentials = self.credentials.clone();
                let key = tokio::task::spawn_blocking(move || {
                    keys::decode_secret_key(credentials.private_key.trim(), None)
                })
                .await?
                .map_err(|_| PlatformFailure)?;
                let hash = ssh
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|_| PlatformFailure)?
                    .flatten();
                ssh.authenticate_publickey(
                    self.credentials.username.as_str(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|_| PlatformFailure)?
            };
            ensure!(authenticated.success(), PlatformFailure);
            let channel = ssh
                .channel_open_session()
                .await
                .map_err(|_| PlatformFailure)?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|_| PlatformFailure)?;
            let raw = protocol(RawSftpSession::new(channel.into_stream()).await)?;
            let copy = raw.supports_copy;
            Ok(Connection {
                raw,
                _ssh: ssh,
                _guard: guard,
                copy,
            })
        })
        .await
        .map_err(|_| PlatformFailure)?
    }
    async fn checked(raw: &RawSftpSession, path: &str, missing_leaf: bool) -> Result<String> {
        let normalized = Self::normalize(path)?;
        let normalized = normalized.trim_end_matches('/');
        let absolute = if normalized.is_empty() {
            "/".into()
        } else if normalized.starts_with('/') {
            normalized.to_owned()
        } else {
            let current = protocol(raw.realpath(".").await)?;
            let current = current
                .files
                .first()
                .context(PlatformFailure)?
                .filename
                .as_str();
            ensure!(current.starts_with('/'), "invalid SFTP working directory");
            format!("{}/{normalized}", current.trim_end_matches('/'))
        };
        Self::normalize(&absolute)?;
        let mut prefixes = vec!["/".to_owned()];
        let mut prefix = String::new();
        for component in absolute
            .trim_matches('/')
            .split('/')
            .filter(|p| !p.is_empty())
        {
            prefix.push('/');
            prefix.push_str(component);
            prefixes.push(prefix.clone());
        }
        for (index, prefix) in prefixes.iter().enumerate() {
            let leaf = index + 1 == prefixes.len();
            let attrs = match raw.lstat(prefix).await {
                Ok(attrs) => attrs.attrs,
                Err(error) if leaf && missing_leaf && missing(&error) => return Ok(absolute),
                Err(_) => return Err(PlatformFailure.into()),
            };
            let kind = attrs.file_type();
            ensure!(
                !matches!(kind, FileType::Symlink | FileType::Other) && (leaf || kind.is_dir()),
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "remote symbolic/special path is forbidden"
                )
            );
        }
        Ok(absolute)
    }
    async fn listing(raw: &RawSftpSession, path: &str) -> Result<Vec<Entry>> {
        let target = Self::normalize(path)?;
        let checked = Self::checked(raw, path, false).await?;
        let handle = protocol(raw.opendir(checked).await)?.handle;
        let mut entries = vec![];
        let mut names_bytes = 0usize;
        loop {
            let page = match raw.readdir(&handle).await {
                Ok(page) => page,
                Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => break,
                Err(_) => return Err(PlatformFailure.into()),
            };
            if page.files.is_empty() && page.end {
                break;
            }
            ensure!(!page.files.is_empty(), PlatformFailure);
            let end = page.end;
            for file in page.files {
                if !safe_segment(&file.filename) {
                    continue;
                }
                names_bytes = names_bytes
                    .checked_add(file.filename.len())
                    .context(PlatformFailure)?;
                ensure!(
                    entries.len() < 100_000 && names_bytes <= 8 * 1024 * 1024,
                    PlatformFailure
                );
                let attrs = file.attrs;
                let kind = attrs.file_type();
                let dir = kind.is_dir();
                let date = attrs.mtime.unwrap_or(0);
                let name = file.filename;
                let full = if target.ends_with('/') {
                    format!("{target}{name}")
                } else {
                    format!("{target}/{name}")
                };
                entries.push(Entry {
                    name: name.clone(),
                    path: full,
                    is_directory: dir,
                    size: if dir {
                        -1
                    } else {
                        attrs.size.unwrap_or(0).try_into()?
                    },
                    created_date: date,
                    updated_date: date,
                    is_hidden: name.starts_with('.'),
                    is_symbolic_link: kind.is_symlink(),
                    is_symbolic_link_known: attrs.type_known(),
                    reference: None,
                });
            }
            if end {
                break;
            }
        }
        status(raw.close(handle).await)?;
        Ok(entries)
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        Self::normalize(path)?;
        let connection = self.connect().await?;
        Self::listing(&connection.raw, path).await
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        Self::normalize(path)?;
        let connection = self.connect().await?;
        let raw = &connection.raw;
        let path = Self::checked(raw, path, false).await?;
        let handle = protocol(raw.open(path, OpenFlags::READ).await)?.handle;
        let mut offset = 0u64;
        loop {
            let data = match raw.read(&handle, offset, 64 * 1024).await {
                Ok(data) => data.data,
                Err(SftpError::Status(s)) if s.status_code == StatusCode::Eof => break,
                Err(_) => return Err(PlatformFailure.into()),
            };
            ensure!(!data.is_empty() && data.len() <= 64 * 1024, PlatformFailure);
            offset = offset
                .checked_add(data.len() as u64)
                .context(PlatformFailure)?;
            output
                .send(Ok((data, size.max(0))))
                .await
                .map_err(|_| PlatformFailure)?;
        }
        status(raw.close(handle).await)?;
        Ok(())
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        mut input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<bool> {
        Self::normalize(path)?;
        let connection = self.connect().await?;
        let raw = &connection.raw;
        let path = Self::checked(raw, path, true).await?;
        let handle = protocol(
            raw.open(
                path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await,
        )?
        .handle;
        let mut offset = 0u64;
        while let Some(bytes) = input.recv().await {
            for part in bytes.chunks(32 * 1024) {
                ensure!(
                    size < 0 || part.len() as u64 <= (size as u64).saturating_sub(offset),
                    ResourceUnavailable("upload length exceeded")
                );
                status(raw.write(&handle, offset, part.to_vec()).await)?;
                offset = offset
                    .checked_add(part.len() as u64)
                    .context(PlatformFailure)?;
                consumed.store(offset, Ordering::Release);
            }
        }
        ensure!(
            size < 0 || offset == size as u64,
            ResourceUnavailable("upload length mismatch")
        );
        status(raw.close(handle).await)
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        destination: &str,
        directory: bool,
    ) -> Result<bool> {
        let normalized = Self::normalize(path)?;
        if matches!(operation, "/copy" | "/rename" | "/move") {
            Self::normalize(destination)?;
        }
        if operation == "/delete-empty-directory" {
            ensure!(
                !normalized.trim_matches('/').trim().is_empty(),
                "cannot remove storage root"
            );
        }
        if operation == "/move" {
            let source = normalized.trim_end_matches('/');
            let target = Self::normalize(destination)?;
            let target = target.trim_end_matches('/');
            ensure!(
                !source.is_empty()
                    && !target.is_empty()
                    && source != target
                    && !target.starts_with(&format!("{source}/")),
                "invalid move destination"
            );
        }
        let connection = self.connect().await?;
        let raw = &connection.raw;
        if operation == "/move" {
            let (parent, name) = destination.rsplit_once('/').unwrap_or(("/", destination));
            let entries = Self::listing(raw, if parent.is_empty() { "/" } else { parent })
                .await
                .map_err(|_| ResourceUnavailable("cannot verify move destination is absent"))?;
            ensure!(
                !entries.iter().any(|e| e.name == name),
                ResourceUnavailable("move target already exists")
            );
        }
        let from = Self::checked(raw, path, matches!(operation, "/create" | "/mkdir")).await?;
        match operation {
            "/mkdir" => status(raw.mkdir(from).await),
            "/create" => {
                let handle = protocol(
                    raw.open(
                        from,
                        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                    )
                    .await,
                )?
                .handle;
                status(raw.close(handle).await)
            }
            "/delete" | "/delete-empty-directory" => {
                if directory || operation == "/delete-empty-directory" {
                    status(raw.rmdir(from).await)
                } else {
                    status(raw.remove(from).await)
                }
            }
            "/rename" | "/move" => {
                let to = Self::checked(raw, destination, true).await?;
                status(raw.rename(from, to).await)
            }
            "/copy" => {
                ensure!(connection.copy, PlatformFailure);
                let to = Self::checked(raw, destination, true).await?;
                let mut bytes = vec![];
                for part in [from.as_bytes(), to.as_bytes()] {
                    bytes.extend(u32::try_from(part.len())?.to_be_bytes());
                    bytes.extend(part);
                }
                bytes.push(1);
                status(raw.extended("copy-file", bytes).await)
            }
            _ => Err(PlatformFailure.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_patterns_are_port_scoped_negation_aware_and_hash_checked() {
        assert!(hosts_match(
            &HostPatterns::Patterns(vec!["*.example.test".into()]),
            "a.example.test",
            22
        ));
        assert!(!hosts_match(
            &HostPatterns::Patterns(vec!["*.example.test".into()]),
            "a.example.test",
            2222
        ));
        assert!(hosts_match(
            &HostPatterns::Patterns(vec!["[*.example.test]:2222".into()]),
            "A.example.test",
            2222
        ));
        assert!(!hosts_match(
            &HostPatterns::Patterns(vec![
                "[*.example.test]:2222".into(),
                "![blocked.example.test]:2222".into()
            ]),
            "blocked.example.test",
            2222
        ));
        let salt = b"fixed-salt".to_vec();
        let hash = <Hmac<Sha1> as Mac>::new_from_slice(&salt)
            .unwrap()
            .chain_update("[::1]:2222")
            .finalize()
            .into_bytes()
            .into();
        let patterns = HostPatterns::HashedName { salt, hash };
        assert!(hosts_match(&patterns, "::1", 2222));
        assert!(!hosts_match(&patterns, "::1", 22));
        assert!(Sftp::normalize("/name \n").is_ok());
        assert!(Sftp::normalize("/../outside").is_err());
        assert!(Sftp::normalize("/embedded\0name").is_err());
    }
}
