use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::{Entry, safe_segment},
};
use anyhow::{Context, Result, ensure};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;

#[derive(Clone)]
pub(crate) struct Attributes {
    pub kind: u32,
    pub size: u64,
    pub modified: i64,
}
impl Attributes {
    pub fn regular(&self) -> Result<()> {
        ensure!(
            self.kind == 1,
            ResourceUnavailable("NFS source is not a regular file")
        );
        Ok(())
    }
    pub fn directory(&self) -> Result<()> {
        ensure!(
            self.kind == 2,
            ResourceUnavailable("NFS source is not a directory")
        );
        Ok(())
    }
    pub fn no_link(&self) -> Result<()> {
        ensure!(
            self.kind != 5,
            ResourceUnavailable("NFS symbolic links are not followed")
        );
        Ok(())
    }
}
pub(crate) struct Node {
    pub handle: Vec<u8>,
    pub attributes: Attributes,
}
#[derive(Debug)]
pub(crate) struct Status(pub u32);
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NFS status {}", self.0)
    }
}
impl std::error::Error for Status {}
pub(crate) fn status(code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(Status(code)).context(PlatformFailure))
    }
}
pub(crate) fn components(path: &str) -> Result<Vec<&str>> {
    ensure!(
        path.encode_utf16().count() <= 16 * 1024 && !path.chars().any(char::is_control),
        "invalid NFS path"
    );
    ensure!(
        path.is_empty() || path.starts_with('/'),
        "NFS path must be absolute within the export"
    );
    let path = path.trim_matches('/');
    let parts = if path.is_empty() {
        vec![]
    } else {
        path.split('/').collect::<Vec<_>>()
    };
    ensure!(
        parts.iter().all(|s| safe_segment(s)),
        "invalid NFS path component"
    );
    Ok(parts)
}
pub(crate) fn leaf(path: &str) -> Result<(String, String)> {
    let mut parts = components(path)?;
    let name = parts
        .pop()
        .context("NFS export root cannot be modified")?
        .to_owned();
    Ok((format!("/{}", parts.join("/")), name))
}
pub(crate) fn entry(parent: &str, name: String, attr: Attributes) -> Result<Entry> {
    ensure!(
        safe_segment(&name) && !name.chars().any(char::is_control),
        "invalid NFS entry name"
    );
    Ok(Entry {
        path: format!("{}/{}", parent.trim_end_matches('/'), name),
        is_hidden: name.starts_with('.'),
        name,
        is_directory: attr.kind == 2,
        size: if attr.kind == 2 {
            -1
        } else {
            i64::try_from(attr.size).map_err(|_| PlatformFailure)?
        },
        created_date: 0,
        updated_date: attr.modified,
        is_symbolic_link: attr.kind == 5,
        is_symbolic_link_known: true,
        reference: None,
    })
}
pub(crate) struct Upload {
    receiver: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    position: usize,
    offered: usize,
    size: u64,
    offset: u64,
    consumed: Arc<AtomicU64>,
}
impl Upload {
    pub fn new(
        size: i64,
        receiver: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<Self> {
        ensure!(size >= 0, "NFS upload requires a known size");
        Ok(Self {
            receiver,
            pending: vec![],
            position: 0,
            offered: 0,
            size: size as u64,
            offset: 0,
            consumed,
        })
    }
    pub async fn next(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        while self.position == self.pending.len() {
            let Some(bytes) = self.receiver.recv().await else {
                ensure!(
                    self.offset == self.size,
                    ResourceUnavailable("NFS upload ended early")
                );
                return Ok(None);
            };
            ensure!(
                bytes.len() as u64 <= self.size - self.offset,
                ResourceUnavailable("NFS upload length exceeded")
            );
            self.pending = bytes;
            self.position = 0;
        }
        self.offered = (self.pending.len() - self.position).min(64 * 1024);
        Ok(Some((
            self.offset,
            self.pending[self.position..self.position + self.offered].to_vec(),
        )))
    }
    pub fn advance(&mut self, count: usize) -> Result<()> {
        ensure!(
            count > 0 && count <= self.offered,
            ResourceUnavailable("invalid NFS short write")
        );
        self.position += count;
        self.offset += count as u64;
        self.offered = 0;
        self.consumed.store(self.offset, Ordering::Release);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn nfs_paths_short_writes_and_terminal_lengths_match_pinned_behavior() {
        assert_eq!(components("/safe/目录").unwrap(), ["safe", "目录"]);
        for p in [
            "/safe/../outside",
            "relative",
            "/safe/\\outside",
            "/safe/\nfile",
        ] {
            assert!(components(p).is_err());
        }
        let (sender, receiver) = mpsc::channel(1);
        sender.send(vec![1, 2, 3, 4, 5]).await.unwrap();
        drop(sender);
        let consumed = Arc::new(AtomicU64::new(0));
        let mut input = Upload::new(5, receiver, consumed.clone()).unwrap();
        for offset in 0..5 {
            let (position, bytes) = input.next().await.unwrap().unwrap();
            assert_eq!(position, offset);
            assert_eq!(bytes[0] as u64, offset + 1);
            input.advance(1).unwrap();
        }
        assert!(input.next().await.unwrap().is_none());
        assert_eq!(consumed.load(Ordering::Acquire), 5);
        let (sender, receiver) = mpsc::channel(1);
        drop(sender);
        assert!(
            Upload::new(3, receiver, consumed.clone())
                .unwrap()
                .next()
                .await
                .is_err()
        );
        let (sender, receiver) = mpsc::channel(1);
        sender.send(vec![1]).await.unwrap();
        drop(sender);
        let mut input = Upload::new(1, receiver, consumed).unwrap();
        input.next().await.unwrap();
        assert!(input.advance(0).is_err());
        assert!(input.advance(2).is_err());
    }
}
