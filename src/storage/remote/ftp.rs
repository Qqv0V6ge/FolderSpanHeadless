use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::{DownloadPart, Entry, endpoint, safe_segment},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Local, TimeZone, Utc};
use serde::Deserialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use suppaftp::{
    Encoding, FtpError, Mode, Status,
    list::File,
    tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Default, Deserialize)]
enum PathEncoding {
    #[default]
    Auto,
    Utf8,
    Gb18030,
    ShiftJis,
    Cp949,
    Windows1251,
}
impl PathEncoding {
    fn codec(self) -> &'static encoding_rs::Encoding {
        match self {
            Self::Auto | Self::Utf8 => encoding_rs::UTF_8,
            Self::Gb18030 => encoding_rs::GB18030,
            Self::ShiftJis => encoding_rs::SHIFT_JIS,
            Self::Cp949 => encoding_rs::EUC_KR,
            Self::Windows1251 => encoding_rs::WINDOWS_1251,
        }
    }
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Extras {
    passive_mode: bool,
    ftps_enabled: bool,
    path_encoding: PathEncoding,
}
impl Default for Extras {
    fn default() -> Self {
        Self {
            passive_mode: true,
            ftps_enabled: false,
            path_encoding: PathEncoding::Auto,
        }
    }
}
#[derive(Debug)]
struct Codec(&'static encoding_rs::Encoding);
impl Encoding for Codec {
    fn decode(&self, bytes: &[u8]) -> String {
        self.0.decode_without_bom_handling(bytes).0.into_owned()
    }
    fn encode(&self, text: &str) -> std::io::Result<Vec<u8>> {
        let (bytes, _, errors) = self.0.encode(text);
        if errors {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path cannot be represented in FTP encoding",
            ));
        }
        Ok(bytes.into_owned())
    }
}
struct Credentials {
    username: String,
    password: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Clone)]
pub struct Ftp {
    host: String,
    port: u16,
    separator: String,
    credentials: Arc<Credentials>,
    extras: Extras,
    tls: Arc<rustls::ClientConfig>,
}
fn failure(error: FtpError) -> anyhow::Error {
    if matches!(error, FtpError::UnexpectedResponse(_)) {
        ResourceUnavailable("FTP server rejected operation").into()
    } else {
        PlatformFailure.into()
    }
}
fn copy_failure(error: FtpError) -> anyhow::Error {
    if let FtpError::UnexpectedResponse(response) = &error
        && [202, 500, 502, 504].contains(&response.status.code())
    {
        return PlatformFailure.into();
    }
    failure(error)
}
fn boolean(result: suppaftp::FtpResult<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(FtpError::UnexpectedResponse(_)) => Ok(false),
        Err(e) => Err(failure(e)),
    }
}
impl Ftp {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        separator: &str,
        extras: &serde_json::Value,
    ) -> Result<Self> {
        let (host, port) = endpoint(host, 21)?;
        ensure!(
            !username.contains(['\r', '\n', '\0']) && !password.contains(['\r', '\n', '\0']),
            "invalid FTP credentials"
        );
        let extras =
            serde_json::from_value(extras.get("ftp").cloned().unwrap_or(serde_json::json!({})))?;
        let tls = Arc::new(crate::network::tls_client::ftp_config()?);
        Ok(Self {
            host,
            port,
            separator: if separator.is_empty() {
                "/".into()
            } else {
                separator.into()
            },
            credentials: Arc::new(Credentials {
                username: if username.trim().is_empty() {
                    "anonymous".into()
                } else {
                    username.into()
                },
                password: password.into(),
            }),
            extras,
            tls,
        })
    }
    fn path<'a>(&'a self, path: &'a str) -> Result<&'a str> {
        let path = if path.trim().is_empty() {
            &self.separator
        } else {
            path
        };
        let normal = path.replace('\\', "/");
        let parts = normal.trim_matches('/');
        ensure!(
            !path.contains(['\r', '\n', '\0'])
                && (parts.is_empty() || parts.split('/').all(safe_segment)),
            "invalid FTP path"
        );
        Ok(path)
    }
    async fn connect(&self) -> Result<AsyncRustlsFtpStream> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut ftp = AsyncRustlsFtpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(failure)?;
            ftp.set_encoding(Codec(self.extras.path_encoding.codec()))
                .await;
            if self.extras.ftps_enabled {
                let connector =
                    AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(self.tls.clone()));
                ftp = ftp
                    .into_secure(connector, &self.host)
                    .await
                    .map_err(|_| PlatformFailure)?;
            }
            ftp.login(
                self.credentials.username.as_str(),
                self.credentials.password.as_str(),
            )
            .await
            .map_err(failure)?;
            ftp.transfer_type(suppaftp::types::FileType::Binary)
                .await
                .map_err(failure)?;
            ftp.set_passive_nat_workaround(true);
            if self.extras.passive_mode {
                ftp.set_mode(if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
                    Mode::ExtendedPassive
                } else {
                    Mode::Passive
                });
            } else {
                ftp = ftp.active_mode(Duration::from_secs(10));
            }
            Ok(ftp)
        })
        .await
        .map_err(|_| PlatformFailure)?
    }
    fn parse(&self, path: &str, bytes: &[u8]) -> Result<Vec<Entry>> {
        let text = self
            .extras
            .path_encoding
            .codec()
            .decode_without_bom_handling(bytes)
            .0;
        let mut entries = vec![];
        for line in text
            .lines()
            .filter(|s| !s.is_empty() && !s.starts_with("total "))
        {
            ensure!(entries.len() < 100_000, PlatformFailure);
            let file: File = line.parse().map_err(|_| PlatformFailure)?;
            let name = file.name();
            if !safe_segment(name) {
                continue;
            }
            let dir = file.is_directory();
            let date: DateTime<Utc> = file.modified().into();
            let date = Local
                .from_local_datetime(&date.naive_utc())
                .latest()
                .map(|v| v.timestamp_millis())
                .unwrap_or(0);
            let full = if path.ends_with(&self.separator) {
                format!("{path}{name}")
            } else {
                format!("{path}{}{name}", self.separator)
            };
            entries.push(Entry {
                name: name.to_owned(),
                path: full,
                is_directory: dir,
                size: if dir { -1 } else { file.size().try_into()? },
                created_date: date,
                updated_date: date,
                is_hidden: name.starts_with('.'),
                is_symbolic_link: file.is_symlink(),
                is_symbolic_link_known: true,
                reference: None,
            });
        }
        Ok(entries)
    }
    async fn list_with(&self, ftp: &mut AsyncRustlsFtpStream, path: &str) -> Result<Vec<Entry>> {
        let path = self.path(path)?;
        let (_, mut stream) = ftp
            .custom_data_command(
                format!("LIST -a {path}"),
                &[Status::AboutToSend, Status::AlreadyOpen],
            )
            .await
            .map_err(failure)?;
        let mut bytes = vec![];
        (&mut stream)
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, PlatformFailure);
        stream.finish().await.map_err(failure)?;
        let owner = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || owner.parse(&path, &bytes)).await?
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        self.path(path)?;
        let mut ftp = self.connect().await?;
        tokio::time::timeout(Duration::from_secs(300), self.list_with(&mut ftp, path))
            .await
            .map_err(|_| PlatformFailure)?
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let path = self.path(path)?;
        let mut ftp = self.connect().await?;
        let mut stream = ftp.retr_as_stream(path).await.map_err(failure)?;
        let mut bytes = vec![0u8; 64 * 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(300), stream.read(&mut bytes))
                .await
                .map_err(|_| PlatformFailure)?
                .map_err(|_| PlatformFailure)?;
            if n == 0 {
                break;
            }
            output
                .send(Ok((bytes[..n].to_vec(), size.max(0))))
                .await
                .map_err(|_| PlatformFailure)?;
        }
        tokio::time::timeout(Duration::from_secs(300), stream.finish())
            .await
            .map_err(|_| PlatformFailure)?
            .map_err(failure)?;
        Ok(())
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        mut input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<bool> {
        let path = self.path(path)?;
        let mut ftp = self.connect().await?;
        let mut stream = ftp.put_with_stream(path).await.map_err(failure)?;
        let mut count = 0u64;
        while let Some(bytes) = input.recv().await {
            count = count
                .checked_add(bytes.len() as u64)
                .context(PlatformFailure)?;
            ensure!(size < 0 || count <= size as u64, PlatformFailure);
            tokio::time::timeout(Duration::from_secs(300), stream.write_all(&bytes))
                .await
                .map_err(|_| PlatformFailure)?
                .map_err(|_| PlatformFailure)?;
            consumed.store(count, Ordering::Release);
        }
        ensure!(size < 0 || count == size as u64, PlatformFailure);
        tokio::time::timeout(Duration::from_secs(300), stream.finish())
            .await
            .map_err(|_| PlatformFailure)?
            .map_err(failure)?;
        Ok(true)
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        new_path: &str,
        directory: bool,
    ) -> Result<bool> {
        let path = self.path(path)?;
        if matches!(operation, "/copy" | "/rename" | "/move") {
            self.path(new_path)?;
        }
        if operation == "/delete-empty-directory" {
            ensure!(
                !path.trim_matches(['/', '\\']).trim().is_empty(),
                "cannot delete storage root"
            );
        }
        if operation == "/move" {
            let source = path.replace('\\', "/");
            let source = source.trim_end_matches('/');
            let target = new_path.replace('\\', "/");
            let target = target.trim_end_matches('/');
            ensure!(
                !source.is_empty()
                    && !target.is_empty()
                    && source != target
                    && !target.starts_with(&format!("{source}/")),
                "invalid move destination"
            );
        }
        let mut ftp = self.connect().await?;
        tokio::time::timeout(Duration::from_secs(300), async {
            match operation {
                "/mkdir" => boolean(ftp.mkdir(path).await),
                "/create" => match ftp.put_with_stream(path).await {
                    Ok(stream) => boolean(stream.finish().await),
                    Err(error) => boolean(Err(error)),
                },
                "/delete" | "/delete-empty-directory" => {
                    if directory || operation == "/delete-empty-directory" {
                        boolean(ftp.rmdir(path).await)
                    } else {
                        boolean(ftp.rm(path).await)
                    }
                }
                "/rename" => boolean(ftp.rename(path, new_path).await),
                "/move" => {
                    let (parent, name) = new_path.rsplit_once('/').unwrap_or(("/", new_path));
                    let entries = self
                        .list_with(&mut ftp, if parent.is_empty() { "/" } else { parent })
                        .await?;
                    ensure!(
                        !entries.iter().any(|e| e.name == name),
                        ResourceUnavailable("move target already exists")
                    );
                    boolean(ftp.rename(path, new_path).await)
                }
                "/copy" => {
                    ftp.custom_command(
                        format!("SITE CPFR {path}"),
                        &[
                            Status::File,
                            Status::RequestedFileActionOk,
                            Status::RequestFilePending,
                            Status::CommandOk,
                        ],
                    )
                    .await
                    .map_err(copy_failure)?;
                    ftp.custom_command(
                        format!("SITE CPTO {new_path}"),
                        &[Status::RequestedFileActionOk, Status::CommandOk],
                    )
                    .await
                    .map_err(copy_failure)?;
                    Ok(true)
                }
                _ => Err(PlatformFailure.into()),
            }
        })
        .await
        .map_err(|_| PlatformFailure)?
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodings_endpoints_and_listing_safety() {
        for (label, codec, text) in [
            (PathEncoding::Gb18030, encoding_rs::GB18030, "中文.txt"),
            (PathEncoding::ShiftJis, encoding_rs::SHIFT_JIS, "日本語.txt"),
            (PathEncoding::Cp949, encoding_rs::EUC_KR, "한국어.txt"),
            (
                PathEncoding::Windows1251,
                encoding_rs::WINDOWS_1251,
                "файл.txt",
            ),
        ] {
            let encoded = Codec(label.codec()).encode(text).unwrap();
            assert_eq!(Codec(codec).decode(&encoded), text);
        }
        assert_eq!(endpoint("[::1]:2121", 21).unwrap(), ("::1".into(), 2121));
        assert_eq!(endpoint("::1", 21).unwrap(), ("::1".into(), 21));
        assert!(endpoint("ftp://example.test", 21).is_err());
        let c = Ftp::new("localhost", "", "", "/", &serde_json::json!({})).unwrap();
        assert!(c.path("/../escape").is_err());
        assert!(c.path("/file\r\nDELE /secret").is_err());
        let entries=c.parse("/",b"-rw-r--r-- 1 user group 3 Jan 1 2020 a file \r\nlrwxrwxrwx 1 user group 3 Jan 1 2020 link -> outside\r\ndrwxr-xr-x 1 user group 0 Jan 1 2020 child\r\n-rw-r--r-- 1 user group 0 Jan 1 2020 ..\r\n").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "a file ");
        assert!(entries[1].is_symbolic_link);
        assert_eq!(entries[1].path, "/link");
        assert_eq!(entries[2].size, -1);
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    #[tokio::test]
    async fn explicit_ftps_checks_identity_and_encrypts_both_sockets() {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = root.path().join("cert.pem");
        let private = root.path().join("key.pem");
        std::fs::write(&cert, key.cert.pem()).unwrap();
        std::fs::write(&private, key.key_pair.serialize_pem()).unwrap();
        let mut peer = crate::ftp_test_peer::Peer::start("utf-8", Some((&cert, &private))).await;
        let mut client = Ftp::new(
            &format!("localhost:{}", peer.port),
            "alice",
            "secret",
            "/",
            &serde_json::json!({"ftp":{"ftpsEnabled":true}}),
        )
        .unwrap();
        assert!(
            client
                .list("/")
                .await
                .unwrap()
                .iter()
                .any(|e| e.name == "中文 &.txt")
        );
        client.extras.passive_mode = false;
        let (input, receiver) = mpsc::channel(1);
        input.send(b"private bytes".to_vec()).await.unwrap();
        drop(input);
        let consumed = Arc::new(AtomicU64::new(0));
        assert!(
            client
                .upload("/secure", 13, receiver, consumed.clone())
                .await
                .unwrap()
        );
        let (output, mut data) = mpsc::channel(1);
        let reader = client.clone();
        let task = tokio::spawn(async move { reader.download("/secure", 13, &output).await });
        let mut downloaded = vec![];
        while let Some(part) = data.recv().await {
            downloaded.extend(part.unwrap().0);
        }
        task.await.unwrap().unwrap();
        assert_eq!(downloaded, b"private bytes");
        let records = peer.records();
        assert!(
            records
                .iter()
                .filter(|r| r["operation"] == "DATA_TLS")
                .count()
                >= 3
        );
        assert!(
            records
                .iter()
                .filter(|r| r["operation"] == "DATA_TLS")
                .all(|r| r["secure"] == true)
        );
        assert!(
            records
                .iter()
                .any(|r| r["operation"] == "PROT" && r["argument"] == "P")
        );
        peer.close().await;
    }
}
