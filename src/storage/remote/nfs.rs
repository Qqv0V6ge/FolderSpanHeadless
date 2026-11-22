mod common;
mod rpc;
mod v3;
mod v4;
mod xdr;

use super::{DownloadPart, Entry};
use crate::management::reply::{PlatformFailure, ResourceUnavailable};
use anyhow::{Context, Result, ensure};
use common::{Upload, components, status};
use rpc::{Auth, Rpc};
use serde::Deserialize;
use std::sync::{Arc, atomic::AtomicU64};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use v3::Nfs3;
use v4::{Identity, Nfs4};
use xdr::build;

#[derive(Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Options {
    version: u32,
    export_path: String,
    uid: i32,
    gid: i32,
    groups: Vec<i32>,
    mount_port: i32,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            version: 4,
            export_path: "/".into(),
            uid: 0,
            gid: 0,
            groups: vec![],
            mount_port: 0,
        }
    }
}
#[derive(Clone)]
pub struct Nfs {
    host: String,
    port: u16,
    options: Arc<Options>,
    identity: Arc<Identity>,
}
enum FileSystem {
    V3(Nfs3),
    V4(Nfs4),
}
impl Nfs {
    pub fn new(host: &str, extras: &serde_json::Value) -> Result<Self> {
        let options: Options =
            serde_json::from_value(extras.get("nfs").cloned().unwrap_or(serde_json::json!({})))?;
        ensure!(
            matches!(options.version, 3 | 4),
            "supported NFS versions are v3 and v4.0"
        );
        components(&options.export_path)?;
        ensure!(
            options.uid >= 0
                && options.gid >= 0
                && options.groups.len() <= 16
                && options.groups.iter().all(|g| *g >= 0),
            "invalid NFS AUTH_SYS identity"
        );
        ensure!(
            (0..=65535).contains(&options.mount_port),
            "invalid NFS mount port"
        );
        let address = if host.contains("://") {
            host.to_owned()
        } else {
            format!("nfs://{host}")
        };
        let address = Url::parse(&address)?;
        ensure!(
            address.scheme() == "nfs"
                && address.username().is_empty()
                && address.password().is_none_or(str::is_empty)
                && matches!(address.path(), "" | "/")
                && address.query().is_none_or(str::is_empty)
                && address.fragment().is_none_or(str::is_empty),
            "invalid NFS server; configure the export separately"
        );
        let host = match address.host().context("NFS host required")? {
            Host::Domain(host) => host.to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let port = address.port().filter(|p| *p > 0).unwrap_or(2049);
        Ok(Self {
            host,
            port,
            options: Arc::new(options),
            identity: Arc::new(Identity::new()),
        })
    }
    async fn connect(&self, port: u16) -> Result<Arc<Rpc>> {
        Ok(Arc::new(
            Rpc::connect(
                &self.host,
                port,
                Auth {
                    uid: self.options.uid as u32,
                    gid: self.options.gid as u32,
                    groups: self.options.groups.iter().map(|g| *g as u32).collect(),
                },
            )
            .await?,
        ))
    }
    async fn mount_port(&self, mapper_port: u16) -> Result<u16> {
        let mapper = self.connect(mapper_port).await?;
        let mut r = mapper
            .call(
                100000,
                2,
                3,
                build(|w| {
                    w.u32(100005);
                    w.u32(3);
                    w.u32(6);
                    w.u32(0);
                }),
            )
            .await?;
        let port = r.u32()?;
        r.end()?;
        ensure!(
            (1..=65535).contains(&port),
            ResourceUnavailable("NFSv3 mount service unavailable")
        );
        Ok(port as u16)
    }
    async fn mount(&self) -> Result<Vec<u8>> {
        let port = if self.options.mount_port > 0 {
            self.options.mount_port as u16
        } else {
            self.mount_port(111).await?
        };
        let mount = self.connect(port).await?;
        let mut r = mount
            .call(
                100005,
                3,
                1,
                build(|w| {
                    w.string(if self.options.export_path.is_empty() {
                        "/"
                    } else {
                        &self.options.export_path
                    })
                }),
            )
            .await?;
        status(r.u32()?)?;
        let handle = r.opaque(64)?;
        let count = r.u32()?;
        ensure!(
            (1..=64).contains(&count),
            ResourceUnavailable("invalid NFS mount authentication list")
        );
        let mut sys = false;
        for _ in 0..count {
            if r.u32()? == 1 {
                sys = true;
            }
        }
        ensure!(
            sys,
            ResourceUnavailable("NFS export does not support AUTH_SYS")
        );
        r.end()?;
        Ok(handle)
    }
    async fn file_system(&self) -> Result<FileSystem> {
        let root = if self.options.version == 3 {
            Some(self.mount().await?)
        } else {
            None
        };
        let rpc = self.connect(self.port).await?;
        Ok(if let Some(root) = root {
            FileSystem::V3(Nfs3 { rpc, root })
        } else {
            FileSystem::V4(Nfs4 {
                rpc,
                export: self.options.export_path.clone(),
                identity: self.identity.clone(),
            })
        })
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        match self.file_system().await? {
            FileSystem::V3(f) => f.list(path).await,
            FileSystem::V4(f) => f.list(path).await,
        }
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let fs = tokio::select! {
            _=cancel.cancelled()=>return Err(ResourceUnavailable("network transfer closed").into()),
            result=self.file_system()=>result?,
        };
        match fs {
            FileSystem::V3(f) => tokio::select! {
                _=cancel.cancelled()=>Err(ResourceUnavailable("network transfer closed").into()),
                result=f.read(path,size,output)=>result,
            },
            FileSystem::V4(f) => f.read(path, size, output, cancel).await,
        }
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
        cancel: &CancellationToken,
    ) -> Result<bool> {
        let mut input = Upload::new(size, input, consumed)?;
        let fs = tokio::select! {
            _=cancel.cancelled()=>return Err(ResourceUnavailable("network transfer closed").into()),
            result=self.file_system()=>result?,
        };
        match fs {
            FileSystem::V3(f) => tokio::select! {
                _=cancel.cancelled()=>return Err(ResourceUnavailable("network transfer closed").into()),
                result=f.write(path,&mut input)=>result,
            }?,
            FileSystem::V4(f) => f.write(path, &mut input, cancel).await?,
        }
        Ok(true)
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        destination: &str,
        directory: bool,
    ) -> Result<bool> {
        if matches!(operation, "/copy" | "/delete-empty-directory") {
            return Err(PlatformFailure.into());
        }
        if operation == "/move" {
            let source = path.replace('\\', "/");
            let source = source.trim_end_matches('/');
            let target = destination.replace('\\', "/");
            let target = target.trim_end_matches('/');
            components(source)?;
            components(target)?;
            ensure!(
                !source.is_empty()
                    && !target.is_empty()
                    && source != target
                    && !target.starts_with(&format!("{source}/")),
                "invalid move destination"
            );
            let (parent, name) = destination.rsplit_once('/').unwrap_or(("/", destination));
            let entries = self
                .list(if parent.is_empty() { "/" } else { parent })
                .await
                .map_err(|_| ResourceUnavailable("cannot verify move destination is absent"))?;
            ensure!(
                !entries.iter().any(|e| e.name == name),
                ResourceUnavailable("move target already exists")
            );
        }
        let fs = self.file_system().await?;
        match fs {
            FileSystem::V3(f) => match operation {
                "/mkdir" | "/create" => f.create(path, operation == "/mkdir").await?,
                "/delete" => f.delete(path, directory).await?,
                "/rename" | "/move" => f.rename(path, destination).await?,
                _ => return Err(PlatformFailure.into()),
            },
            FileSystem::V4(f) => match operation {
                "/mkdir" | "/create" => f.create(path, operation == "/mkdir").await?,
                "/delete" => f.delete(path, directory).await?,
                "/rename" | "/move" => f.rename(path, destination).await?,
                _ => return Err(PlatformFailure.into()),
            },
        }
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn mount_portmapper_uses_tcp_mount_v3_and_rejects_unavailable_or_invalid_ports() {
        use crate::storage::remote::nfs::{
            rpc::record,
            xdr::{Reader, Writer},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            for reported in [20048u32, 0, 65536] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Reader::new(record(&mut stream).await.unwrap());
                let xid = request.u32().unwrap();
                assert_eq!((request.u32().unwrap(), request.u32().unwrap()), (0, 2));
                assert_eq!(
                    (
                        request.u32().unwrap(),
                        request.u32().unwrap(),
                        request.u32().unwrap()
                    ),
                    (100000, 2, 3)
                );
                assert_eq!(request.u32().unwrap(), 1);
                request.opaque(1024).unwrap();
                assert_eq!((request.u32().unwrap(), request.u32().unwrap()), (0, 0));
                for expected in [100005, 3, 6, 0] {
                    assert_eq!(request.u32().unwrap(), expected);
                }
                request.end().unwrap();
                let mut response = Writer::default();
                for value in [xid, 1, 0, 0, 0, 0, reported] {
                    response.u32(value);
                }
                stream
                    .write_u32(0x80000000 | response.0.len() as u32)
                    .await
                    .unwrap();
                stream.write_all(&response.0).await.unwrap();
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            }
        });
        let n = Nfs::new("127.0.0.1", &serde_json::json!({})).unwrap();
        assert_eq!(n.mount_port(port).await.unwrap(), 20048);
        for _ in 0..2 {
            assert!(n.mount_port(port).await.is_err());
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn nfs_configuration_has_pinned_defaults_and_rejects_implicit_exports() {
        let n = Nfs::new("[::1]:0", &serde_json::json!({})).unwrap();
        assert_eq!(n.host, "::1");
        assert_eq!(n.port, 2049);
        assert_eq!(n.options.version, 4);
        for host in [
            "https://example.test",
            "nfs://user:password@example.test",
            "nfs://example.test/implicit",
            "nfs://example.test/?arg=1",
        ] {
            assert!(Nfs::new(host, &serde_json::json!({})).is_err());
        }
        for options in [
            serde_json::json!({"version":2}),
            serde_json::json!({"uid":-1}),
            serde_json::json!({"groups":vec![0;17]}),
            serde_json::json!({"exportPath":"relative"}),
            serde_json::json!({"mountPort":65536}),
        ] {
            assert!(Nfs::new("127.0.0.1", &serde_json::json!({"nfs":options})).is_err());
        }
    }
}
