use crate::{
    management::reply::ResourceUnavailable,
    storage::remote::{
        DownloadPart, Entry,
        nfs::{
            common::{Attributes, Node, Status, Upload, components, entry, leaf, status},
            rpc::Rpc,
            xdr::{Reader, Writer, build},
        },
    },
};
use anyhow::{Result, ensure};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::mpsc;

pub(crate) struct Nfs3 {
    pub rpc: Arc<Rpc>,
    pub root: Vec<u8>,
}
fn attributes(r: &mut Reader) -> Result<Attributes> {
    let kind = r.u32()?;
    r.skip(16)?;
    let size = r.u64()?;
    ensure!(
        size <= i64::MAX as u64,
        ResourceUnavailable("NFS file exceeds supported size")
    );
    r.skip(40)?;
    let modified = r.u32()? as i64 * 1000 + r.u32()? as i64 / 1_000_000;
    r.skip(8)?;
    Ok(Attributes {
        kind,
        size,
        modified,
    })
}
fn optional(r: &mut Reader) -> Result<Option<Attributes>> {
    if r.bool()? {
        Ok(Some(attributes(r)?))
    } else {
        Ok(None)
    }
}
fn wcc(r: &mut Reader) -> Result<()> {
    if r.bool()? {
        r.skip(24)?;
    }
    optional(r)?;
    Ok(())
}
fn set_attributes(w: &mut Writer, mode: Option<u32>, size: Option<u64>) {
    w.bool(mode.is_some());
    if let Some(mode) = mode {
        w.u32(mode);
    }
    w.bool(false);
    w.bool(false);
    w.bool(size.is_some());
    if let Some(size) = size {
        w.u64(size);
    }
    w.u32(0);
    w.u32(0);
}
impl Nfs3 {
    async fn request(&self, procedure: u32, args: Writer) -> Result<Reader> {
        let mut reader = self.rpc.call(100003, 3, procedure, args).await?;
        status(reader.u32()?)?;
        Ok(reader)
    }
    async fn attributes(&self, handle: &[u8]) -> Result<Attributes> {
        let mut r = self.request(1, build(|w| w.opaque(handle))).await?;
        let attributes = attributes(&mut r)?;
        r.end()?;
        Ok(attributes)
    }
    pub async fn resolve(&self, path: &str) -> Result<Node> {
        let mut handle = self.root.clone();
        let mut attributes = self.attributes(&handle).await?;
        for component in components(path)? {
            attributes.directory()?;
            let mut r = self
                .request(
                    3,
                    build(|w| {
                        w.opaque(&handle);
                        w.string(component);
                    }),
                )
                .await?;
            handle = r.opaque(64)?;
            let result = optional(&mut r)?;
            optional(&mut r)?;
            r.end()?;
            attributes = if let Some(attr) = result {
                attr
            } else {
                self.attributes(&handle).await?
            };
            attributes.no_link()?;
        }
        Ok(Node { handle, attributes })
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let node = self.resolve(path).await?;
        node.attributes.directory()?;
        let mut cookie = 0;
        let mut verifier = vec![0; 8];
        let mut cookies = HashSet::new();
        let mut result = vec![];
        let mut total_names = 0usize;
        loop {
            ensure!(
                cookies.insert(cookie),
                ResourceUnavailable("NFS directory cookie cycle")
            );
            let mut r = self
                .request(
                    17,
                    build(|w| {
                        w.opaque(&node.handle);
                        w.u64(cookie);
                        w.fixed(&verifier);
                        w.u32(64 * 1024);
                        w.u32(128 * 1024);
                    }),
                )
                .await?;
            optional(&mut r)?;
            verifier = r.fixed(8)?;
            let mut count = 0;
            while r.bool()? {
                r.u64()?;
                let name = r.string(4096)?;
                cookie = r.u64()?;
                let attr = optional(&mut r)?;
                let handle = if r.bool()? { Some(r.opaque(64)?) } else { None };
                if matches!(name.as_str(), "." | "..") {
                    continue;
                }
                let attr = if let Some(attr) = attr {
                    attr
                } else if let Some(handle) = handle {
                    self.attributes(&handle).await?
                } else {
                    self.resolve(&format!("{}/{}", path.trim_end_matches('/'), name))
                        .await?
                        .attributes
                };
                total_names += name.len();
                ensure!(
                    total_names <= 64 * 1024 * 1024,
                    ResourceUnavailable("NFS directory names exceed byte limit")
                );
                result.push(entry(path, name, attr)?);
                count += 1;
                ensure!(
                    result.len() <= 500_000,
                    ResourceUnavailable("NFS directory exceeds entry limit")
                );
            }
            let eof = r.bool()?;
            r.end()?;
            if eof {
                break;
            }
            ensure!(
                count > 0,
                ResourceUnavailable("NFS directory page made no progress")
            );
        }
        Ok(result)
    }
    pub async fn read(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let node = self.resolve(path).await?;
        node.attributes.regular()?;
        let total = node.attributes.size;
        ensure!(
            size < 0 || total == size as u64,
            ResourceUnavailable("NFS file size changed")
        );
        let mut offset = 0;
        loop {
            let mut r = self
                .request(
                    6,
                    build(|w| {
                        w.opaque(&node.handle);
                        w.u64(offset);
                        w.u32(64 * 1024);
                    }),
                )
                .await?;
            optional(&mut r)?;
            let count = r.u32()? as usize;
            let eof = r.bool()?;
            let bytes = r.opaque(64 * 1024)?;
            r.end()?;
            ensure!(
                count == bytes.len() && count as u64 <= total - offset,
                ResourceUnavailable("invalid NFS read length")
            );
            ensure!(
                count > 0 || eof,
                ResourceUnavailable("NFS read made no progress")
            );
            if count > 0 || total == 0 {
                output
                    .send(Ok((bytes, total as i64)))
                    .await
                    .map_err(|_| ResourceUnavailable("network transfer closed"))?;
            }
            offset += count as u64;
            if eof {
                break;
            }
        }
        ensure!(offset == total, ResourceUnavailable("NFS read ended early"));
        Ok(())
    }
    async fn create_node(&self, path: &str, directory: bool) -> Result<Option<Vec<u8>>> {
        let (parent, name) = leaf(path)?;
        let node = self.resolve(&parent).await?;
        node.attributes.directory()?;
        let mut r = self
            .request(
                if directory { 9 } else { 8 },
                build(|w| {
                    w.opaque(&node.handle);
                    w.string(&name);
                    if !directory {
                        w.u32(1);
                    }
                    set_attributes(
                        w,
                        Some(if directory { 493 } else { 420 }),
                        (!directory).then_some(0),
                    );
                }),
            )
            .await?;
        let handle = if r.bool()? { Some(r.opaque(64)?) } else { None };
        optional(&mut r)?;
        wcc(&mut r)?;
        r.end()?;
        Ok(handle)
    }
    pub async fn create(&self, path: &str, directory: bool) -> Result<()> {
        self.create_node(path, directory).await?;
        Ok(())
    }
    pub async fn write(&self, path: &str, input: &mut Upload) -> Result<()> {
        let node = match self.resolve(path).await {
            Ok(node) => {
                node.attributes.regular()?;
                node
            }
            Err(error) if error.downcast_ref::<Status>().is_some_and(|s| s.0 == 2) => {
                if let Some(handle) = self.create_node(path, false).await? {
                    Node {
                        handle,
                        attributes: Attributes {
                            kind: 1,
                            size: 0,
                            modified: 0,
                        },
                    }
                } else {
                    self.resolve(path).await?
                }
            }
            Err(error) => return Err(error),
        };
        let mut r = self
            .request(
                2,
                build(|w| {
                    w.opaque(&node.handle);
                    set_attributes(w, None, Some(0));
                    w.bool(false);
                }),
            )
            .await?;
        wcc(&mut r)?;
        r.end()?;
        let mut unstable: Option<Vec<u8>> = None;
        while let Some((offset, bytes)) = input.next().await? {
            let mut r = self
                .request(
                    7,
                    build(|w| {
                        w.opaque(&node.handle);
                        w.u64(offset);
                        w.u32(bytes.len() as u32);
                        w.u32(2);
                        w.opaque(&bytes);
                    }),
                )
                .await?;
            wcc(&mut r)?;
            let count = r.u32()? as usize;
            let committed = r.u32()?;
            ensure!(
                committed <= 2,
                ResourceUnavailable("invalid NFS write stability")
            );
            let verifier = r.fixed(8)?;
            r.end()?;
            if let Some(expected) = &unstable {
                ensure!(
                    *expected == verifier,
                    ResourceUnavailable("NFS server restarted during unstable write")
                );
            }
            if committed != 2 {
                unstable = Some(verifier);
            }
            input.advance(count)?;
        }
        if let Some(expected) = unstable {
            let mut r = self
                .request(
                    21,
                    build(|w| {
                        w.opaque(&node.handle);
                        w.u64(0);
                        w.u32(0);
                    }),
                )
                .await?;
            wcc(&mut r)?;
            ensure!(
                r.fixed(8)? == expected,
                ResourceUnavailable("NFS write commit verifier changed")
            );
            r.end()?;
        }
        Ok(())
    }
    pub async fn delete(&self, path: &str, directory: bool) -> Result<()> {
        let node = self.resolve(path).await?;
        node.attributes.no_link()?;
        ensure!(
            (node.attributes.kind == 2) == directory,
            ResourceUnavailable("NFS entry type changed")
        );
        let (parent, name) = leaf(path)?;
        let node = self.resolve(&parent).await?;
        let mut r = self
            .request(
                if directory { 13 } else { 12 },
                build(|w| {
                    w.opaque(&node.handle);
                    w.string(&name);
                }),
            )
            .await?;
        wcc(&mut r)?;
        r.end()
    }
    pub async fn rename(&self, path: &str, destination: &str) -> Result<()> {
        self.resolve(path).await?.attributes.no_link()?;
        let (from_parent, from_name) = leaf(path)?;
        let (to_parent, to_name) = leaf(destination)?;
        let from = self.resolve(&from_parent).await?;
        let to = self.resolve(&to_parent).await?;
        let mut r = self
            .request(
                14,
                build(|w| {
                    w.opaque(&from.handle);
                    w.string(&from_name);
                    w.opaque(&to.handle);
                    w.string(&to_name);
                }),
            )
            .await?;
        wcc(&mut r)?;
        wcc(&mut r)?;
        r.end()
    }
}
