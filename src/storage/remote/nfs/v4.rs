use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::{
        DownloadPart, Entry,
        nfs::{
            common::{Attributes, Node, Upload, components, entry, leaf, status},
            rpc::Rpc,
            xdr::{Reader, Writer, build},
        },
    },
};
use anyhow::{Context, Result, ensure};
use std::{collections::HashSet, future::Future, sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

pub(crate) struct Identity {
    name: [u8; 32],
    verifier: [u8; 8],
    mutex: Mutex<()>,
}
impl Identity {
    pub fn new() -> Self {
        Self {
            name: rand::random(),
            verifier: rand::random(),
            mutex: Mutex::new(()),
        }
    }
}
pub(crate) struct Nfs4 {
    pub rpc: Arc<Rpc>,
    pub export: String,
    pub identity: Arc<Identity>,
}
type Op = (u32, Writer);
struct Compound {
    reader: Reader,
    codes: Vec<u32>,
    overall: u32,
    count: usize,
    processed: usize,
}
impl Compound {
    fn new(mut reader: Reader, codes: Vec<u32>) -> Result<Self> {
        let overall = reader.u32()?;
        reader.string(1024)?;
        let count = reader.u32()? as usize;
        if count == 0 && overall != 0 {
            status(overall)?;
        }
        ensure!(
            count > 0 && count <= codes.len(),
            ResourceUnavailable("invalid NFSv4 compound length")
        );
        Ok(Self {
            reader,
            codes,
            overall,
            count,
            processed: 0,
        })
    }
    fn op(&mut self, code: u32) -> Result<&mut Reader> {
        ensure!(
            self.processed < self.count
                && self.codes.get(self.processed) == Some(&code)
                && self.reader.u32()? == code,
            ResourceUnavailable("unexpected NFSv4 operation")
        );
        status(self.reader.u32()?)?;
        self.processed += 1;
        Ok(&mut self.reader)
    }
    fn end(&self) -> Result<()> {
        ensure!(
            self.overall == 0 && self.count == self.codes.len() && self.processed == self.count,
            ResourceUnavailable("incomplete NFSv4 compound")
        );
        self.reader.end()
    }
}
fn empty() -> Writer {
    Writer::default()
}
fn put(handle: &[u8]) -> Op {
    (22, build(|w| w.opaque(handle)))
}
fn mask() -> Writer {
    build(|w| {
        w.u32(2);
        w.u32((1 << 1) | (1 << 4) | (1 << 20));
        w.u32(1 << 21);
    })
}
fn bitmap(r: &mut Reader) -> Result<Vec<u32>> {
    let count = r.u32()? as usize;
    ensure!(
        count <= 8,
        ResourceUnavailable("NFSv4 bitmap exceeds its limit")
    );
    (0..count).map(|_| r.u32()).collect()
}
fn attributes(r: &mut Reader) -> Result<Attributes> {
    let mask = bitmap(r)?;
    let mut data = Reader::new(r.opaque(4096)?);
    let mut kind = None;
    let mut size = 0;
    let mut modified = 0;
    for (word_index, word) in mask.iter().enumerate() {
        for bit in 0..32 {
            if word & (1u32 << bit) == 0 {
                continue;
            }
            match word_index * 32 + bit {
                1 => kind = Some(data.u32()?),
                4 => {
                    size = data.u64()?;
                    ensure!(
                        size <= i64::MAX as u64,
                        ResourceUnavailable("NFS file exceeds supported size")
                    );
                }
                20 => {
                    data.u64()?;
                }
                53 => {
                    let seconds = data.u64()?;
                    let nanos = data.u32()?;
                    ensure!(
                        nanos < 1_000_000_000 && seconds <= (i64::MAX as u64 / 1000 - 1),
                        ResourceUnavailable("invalid NFS timestamp")
                    );
                    modified = (seconds * 1000 + nanos as u64 / 1_000_000) as i64;
                }
                _ => return Err(ResourceUnavailable("unexpected NFSv4 attribute").into()),
            }
        }
    }
    data.end()?;
    Ok(Attributes {
        kind: kind.context(ResourceUnavailable("NFSv4 file type missing"))?,
        size,
        modified,
    })
}
fn change(r: &mut Reader) -> Result<()> {
    r.bool()?;
    r.u64()?;
    r.u64()?;
    Ok(())
}
fn create_attributes(mode: u32, size: Option<u64>) -> Writer {
    build(|w| {
        w.u32(2);
        w.u32(if size.is_some() { 1 << 4 } else { 0 });
        w.u32(1 << 1);
        w.opaque(
            &build(|values| {
                if let Some(size) = size {
                    values.u64(size);
                }
                values.u32(mode);
            })
            .0,
        );
    })
}
fn ace(r: &mut Reader) -> Result<()> {
    r.u32()?;
    r.u32()?;
    r.u32()?;
    r.string(4096)?;
    Ok(())
}
#[derive(Clone)]
struct OpenFile {
    handle: Vec<u8>,
    state: Vec<u8>,
    sequence: u32,
    client_id: u64,
}
impl Nfs4 {
    async fn compound(&self, ops: Vec<Op>) -> Result<Compound> {
        ensure!(
            !ops.is_empty() && ops.len() <= 64,
            "too many NFSv4 operations"
        );
        let codes = ops.iter().map(|o| o.0).collect::<Vec<_>>();
        let request = build(|w| {
            w.string("FolderSpan");
            w.u32(0);
            w.u32(ops.len() as u32);
            for (code, args) in ops {
                w.u32(code);
                w.fixed(&args.0);
            }
        });
        Compound::new(self.rpc.call(100003, 4, 1, request).await?, codes)
    }
    pub async fn resolve(&self, path: &str) -> Result<Node> {
        let parts = components(&self.export)?
            .into_iter()
            .chain(components(path)?);
        let mut c = self
            .compound(vec![(24, empty()), (10, empty()), (9, mask())])
            .await?;
        c.op(24)?;
        let mut handle = c.op(10)?.opaque(128)?;
        let mut attr = attributes(c.op(9)?)?;
        c.end()?;
        for part in parts {
            attr.directory()?;
            let mut c = self
                .compound(vec![
                    put(&handle),
                    (15, build(|w| w.string(part))),
                    (10, empty()),
                    (9, mask()),
                ])
                .await?;
            c.op(22)?;
            c.op(15)?;
            handle = c.op(10)?.opaque(128)?;
            attr = attributes(c.op(9)?)?;
            attr.no_link()?;
            c.end()?;
        }
        Ok(Node {
            handle,
            attributes: attr,
        })
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let directory = self.resolve(path).await?;
        directory.attributes.directory()?;
        let mut result = vec![];
        let mut cookie = 0;
        let mut verifier = vec![0; 8];
        let mut seen = HashSet::new();
        let mut name_bytes = 0usize;
        loop {
            ensure!(
                seen.insert(cookie),
                ResourceUnavailable("NFSv4 directory cookie cycle")
            );
            let mut args = build(|w| {
                w.u64(cookie);
                w.fixed(&verifier);
                w.u32(64 * 1024);
                w.u32(128 * 1024);
            });
            args.fixed(&mask().0);
            let mut c = self
                .compound(vec![put(&directory.handle), (26, args)])
                .await?;
            c.op(22)?;
            let r = c.op(26)?;
            verifier = r.fixed(8)?;
            let mut count = 0;
            while r.bool()? {
                cookie = r.u64()?;
                let name = r.string(4096)?;
                let attr = attributes(r)?;
                if matches!(name.as_str(), "." | "..") {
                    continue;
                }
                name_bytes += name.len();
                ensure!(
                    name_bytes <= 64 * 1024 * 1024,
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
            c.end()?;
            if eof {
                break;
            }
            ensure!(
                count > 0,
                ResourceUnavailable("NFSv4 directory page made no progress")
            );
        }
        Ok(result)
    }
    async fn client_id(&self) -> Result<u64> {
        let _identity = self.identity.mutex.lock().await;
        let mut c = self
            .compound(vec![(
                35,
                build(|w| {
                    w.fixed(&self.identity.verifier);
                    w.opaque(&self.identity.name);
                    w.u32(0);
                    w.string("tcp");
                    w.string("0.0.0.0.0.0");
                    w.u32(0);
                }),
            )])
            .await?;
        let r = c.op(35)?;
        let id = r.u64()?;
        let confirmation = r.fixed(8)?;
        c.end()?;
        let mut c = self
            .compound(vec![(
                36,
                build(|w| {
                    w.u64(id);
                    w.fixed(&confirmation);
                }),
            )])
            .await?;
        c.op(36)?;
        c.end()?;
        Ok(id)
    }
    async fn open(
        &self,
        path: &str,
        write: bool,
        create: bool,
        guarded: bool,
    ) -> Result<(OpenFile, u32, Option<Vec<u8>>)> {
        let (parent, name) = leaf(path)?;
        let parent = self.resolve(&parent).await?;
        parent.attributes.directory()?;
        let client_id = self.client_id().await?;
        let mut c = self
            .compound(vec![
                put(&parent.handle),
                (
                    18,
                    build(|w| {
                        w.u32(0);
                        w.u32(if write { 2 } else { 1 });
                        w.u32(0);
                        w.u64(client_id);
                        w.opaque(&rand::random::<[u8; 32]>());
                        w.u32(u32::from(create));
                        if create {
                            w.u32(u32::from(guarded));
                            w.fixed(&create_attributes(420, Some(0)).0);
                        }
                        w.u32(0);
                        w.string(&name);
                    }),
                ),
                (10, empty()),
            ])
            .await?;
        c.op(22)?;
        let r = c.op(18)?;
        let state = r.fixed(16)?;
        change(r)?;
        let flags = r.u32()?;
        bitmap(r)?;
        let delegation = match r.u32()? {
            0 => None,
            1 => {
                let state = r.fixed(16)?;
                r.bool()?;
                ace(r)?;
                Some(state)
            }
            2 => {
                let state = r.fixed(16)?;
                r.bool()?;
                match r.u32()? {
                    1 => {
                        r.u64()?;
                    }
                    2 => {
                        r.u32()?;
                        r.u32()?;
                    }
                    _ => return Err(ResourceUnavailable("invalid NFSv4 space limit").into()),
                }
                ace(r)?;
                Some(state)
            }
            _ => return Err(ResourceUnavailable("invalid NFSv4 delegation").into()),
        };
        let handle = c.op(10)?.opaque(128)?;
        c.end()?;
        Ok((
            OpenFile {
                handle,
                state,
                sequence: 1,
                client_id,
            },
            flags,
            delegation,
        ))
    }
    async fn close(&self, file: &OpenFile) -> Result<()> {
        let mut c = self
            .compound(vec![
                put(&file.handle),
                (
                    4,
                    build(|w| {
                        w.u32(file.sequence);
                        w.fixed(&file.state);
                    }),
                ),
            ])
            .await?;
        c.op(22)?;
        c.op(4)?.fixed(16)?;
        c.end()
    }
    async fn with_open<T, F, Fut>(
        &self,
        path: &str,
        write: bool,
        create: bool,
        guarded: bool,
        cancel: &CancellationToken,
        operation: F,
    ) -> Result<T>
    where
        T: Send,
        F: FnOnce(OpenFile) -> Fut + Send,
        Fut: Future<Output = Result<T>> + Send,
    {
        let (mut file, flags, delegation) = tokio::select! {
            _=cancel.cancelled()=>return Err(ResourceUnavailable("network transfer closed").into()),
            result=self.open(path,write,create,guarded)=>result?,
        };
        let result = tokio::select! {
            biased;
            _=cancel.cancelled()=>Err(ResourceUnavailable("network transfer closed").into()),
            result=async {
                if flags&2!=0 {
                    let mut c=self.compound(vec![put(&file.handle),(20,build(|w|{w.fixed(&file.state);w.u32(file.sequence);} ))]).await?;
                    c.op(22)?;file.state=c.op(20)?.fixed(16)?;c.end()?;file.sequence+=1;
                }
                if let Some(state)=delegation {
                    let mut c=self.compound(vec![put(&file.handle),(8,build(|w|w.fixed(&state)))]).await?;
                    c.op(22)?;c.op(8)?;c.end()?;
                }
                let renewal=async {
                    loop {
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        let mut c=self.compound(vec![(30,build(|w|w.u64(file.client_id)))]).await?;
                        c.op(30)?;c.end()?;
                    }
                    #[allow(unreachable_code)] Ok::<T,anyhow::Error>(unreachable!())
                };
                tokio::select! {result=operation(file.clone())=>result,result=renewal=>result}
            }=>result,
        };
        // CLOSE gets its own bounded chance after cancellation; uncertain writes are never replayed.
        let closed = tokio::time::timeout(Duration::from_secs(5), self.close(&file))
            .await
            .map_err(|_| PlatformFailure);
        let value = result?;
        closed??;
        Ok(value)
    }
    pub async fn read(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.with_open(path, false, false, false, cancel, |file| async move {
            let mut c = self.compound(vec![put(&file.handle), (9, mask())]).await?;
            c.op(22)?;
            let attr = attributes(c.op(9)?)?;
            c.end()?;
            attr.regular()?;
            let total = attr.size;
            ensure!(
                size < 0 || total == size as u64,
                ResourceUnavailable("NFS file size changed")
            );
            let mut offset = 0;
            loop {
                let mut c = self
                    .compound(vec![
                        put(&file.handle),
                        (
                            25,
                            build(|w| {
                                w.fixed(&file.state);
                                w.u64(offset);
                                w.u32(64 * 1024);
                            }),
                        ),
                    ])
                    .await?;
                c.op(22)?;
                let r = c.op(25)?;
                let eof = r.bool()?;
                let bytes = r.opaque(64 * 1024)?;
                c.end()?;
                ensure!(
                    bytes.len() as u64 <= total - offset && (!bytes.is_empty() || eof),
                    ResourceUnavailable("invalid NFSv4 read length")
                );
                offset += bytes.len() as u64;
                if !bytes.is_empty() || total == 0 {
                    output
                        .send(Ok((bytes, total as i64)))
                        .await
                        .map_err(|_| ResourceUnavailable("network transfer closed"))?;
                }
                if eof {
                    break;
                }
            }
            ensure!(
                offset == total,
                ResourceUnavailable("NFSv4 read ended early")
            );
            Ok(())
        })
        .await
    }
    pub async fn write(
        &self,
        path: &str,
        input: &mut Upload,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.with_open(path, true, true, false, cancel, |file| async move {
            let mut unstable: Option<Vec<u8>> = None;
            while let Some((offset, bytes)) = input.next().await? {
                let mut c = self
                    .compound(vec![
                        put(&file.handle),
                        (
                            38,
                            build(|w| {
                                w.fixed(&file.state);
                                w.u64(offset);
                                w.u32(2);
                                w.opaque(&bytes);
                            }),
                        ),
                    ])
                    .await?;
                c.op(22)?;
                let r = c.op(38)?;
                let count = r.u32()? as usize;
                let committed = r.u32()?;
                ensure!(
                    committed <= 2,
                    ResourceUnavailable("invalid NFSv4 write stability")
                );
                let verifier = r.fixed(8)?;
                c.end()?;
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
                let mut c = self
                    .compound(vec![
                        put(&file.handle),
                        (
                            5,
                            build(|w| {
                                w.u64(0);
                                w.u32(0);
                            }),
                        ),
                    ])
                    .await?;
                c.op(22)?;
                ensure!(
                    c.op(5)?.fixed(8)? == expected,
                    ResourceUnavailable("NFSv4 commit verifier changed")
                );
                c.end()?;
            }
            Ok(())
        })
        .await
    }
    pub async fn create(&self, path: &str, directory: bool) -> Result<()> {
        if !directory {
            return self
                .with_open(
                    path,
                    true,
                    true,
                    true,
                    &CancellationToken::new(),
                    |_| async { Ok(()) },
                )
                .await;
        }
        let (parent, name) = leaf(path)?;
        let parent = self.resolve(&parent).await?;
        parent.attributes.directory()?;
        let mut c = self
            .compound(vec![
                put(&parent.handle),
                (
                    6,
                    build(|w| {
                        w.u32(2);
                        w.string(&name);
                        w.fixed(&create_attributes(493, None).0);
                    }),
                ),
            ])
            .await?;
        c.op(22)?;
        let r = c.op(6)?;
        change(r)?;
        bitmap(r)?;
        c.end()
    }
    pub async fn delete(&self, path: &str, directory: bool) -> Result<()> {
        let node = self.resolve(path).await?;
        node.attributes.no_link()?;
        ensure!(
            (node.attributes.kind == 2) == directory,
            ResourceUnavailable("NFS entry type changed")
        );
        let (parent, name) = leaf(path)?;
        let parent = self.resolve(&parent).await?;
        let mut c = self
            .compound(vec![put(&parent.handle), (28, build(|w| w.string(&name)))])
            .await?;
        c.op(22)?;
        change(c.op(28)?)?;
        c.end()
    }
    pub async fn rename(&self, path: &str, destination: &str) -> Result<()> {
        self.resolve(path).await?.attributes.no_link()?;
        let (from_parent, from_name) = leaf(path)?;
        let (to_parent, to_name) = leaf(destination)?;
        let from = self.resolve(&from_parent).await?;
        let to = self.resolve(&to_parent).await?;
        let mut c = self
            .compound(vec![
                put(&from.handle),
                (32, empty()),
                put(&to.handle),
                (
                    29,
                    build(|w| {
                        w.string(&from_name);
                        w.string(&to_name);
                    }),
                ),
            ])
            .await?;
        c.op(22)?;
        c.op(32)?;
        c.op(22)?;
        let r = c.op(29)?;
        change(r)?;
        change(r)?;
        c.end()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nfsv4_compound_masks_handles_and_statuses_are_strict() {
        let r = build(|w| {
            w.u32(0);
            w.string("FolderSpan");
            w.u32(2);
            w.u32(22);
            w.u32(0);
            w.u32(10);
            w.u32(0);
            w.opaque(&[255, 128]);
        });
        let mut c = Compound::new(Reader::new(r.0), vec![22, 10]).unwrap();
        c.op(22).unwrap();
        assert_eq!(c.op(10).unwrap().opaque(128).unwrap(), [255, 128]);
        c.end().unwrap();
        let r = build(|w| {
            w.u32(0);
            w.string("");
            w.u32(1);
            w.u32(99);
            w.u32(0);
        });
        assert!(
            Compound::new(Reader::new(r.0), vec![10])
                .unwrap()
                .op(10)
                .is_err()
        );
        let attr = build(|w| {
            w.u32(2);
            w.u32((1 << 1) | (1 << 4) | (1 << 20));
            w.u32(1 << 21);
            w.opaque(
                &build(|v| {
                    v.u32(1);
                    v.u64(1u64 << 40);
                    v.u64(99);
                    v.u64(1577836800);
                    v.u32(1_000_000);
                })
                .0,
            );
        });
        let attr = attributes(&mut Reader::new(attr.0)).unwrap();
        assert_eq!(attr.size, 1u64 << 40);
        assert_eq!(attr.modified, 1577836800001);
        let bad = build(|w| {
            w.u32(1);
            w.u32(1);
            w.opaque(&[]);
        });
        assert!(attributes(&mut Reader::new(bad.0)).is_err());
        let bad = build(|w| {
            w.u32(9);
        });
        assert!(bitmap(&mut Reader::new(bad.0)).is_err());
    }
}
