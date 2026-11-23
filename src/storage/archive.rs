use crate::{
    management::session::Session,
    network::peer::{
        transfer::{Transfer, TransferResult},
        transport::Transport,
    },
    storage::files::FilePolicy,
};
use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use prost::Message;
use serde::Deserialize;
use std::{
    collections::HashSet,
    io::{Read, Write},
    path::{Component, Path},
    sync::Arc,
};
use tokio::sync::mpsc;
pub const MAX_ENTRIES: usize = 512;
pub const MAX_PAYLOAD: u64 = 32 * 1024 * 1024;
pub const MAX_HEADER: usize = 256 * 1024;
pub const MAX_FRAMES: u64 = MAX_PAYLOAD + MAX_ENTRIES as u64 * (MAX_HEADER as u64 + 4) + 4;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub codec: i32,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub source_path: String,
    pub relative_path: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub directory: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub modified_time_millis: i64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub entries: Vec<Entry>,
    pub options: Options,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteRequest {
    pub destination_root_path: String,
    pub expected_entries: usize,
    pub expected_file_bytes: u64,
}
#[derive(Clone, PartialEq, Message)]
struct Prelude {
    #[prost(int32, optional, tag = "1")]
    codec: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    entries: Option<i32>,
    #[prost(int64, optional, tag = "3")]
    file_bytes: Option<i64>,
    #[prost(int64, optional, tag = "4")]
    frame_bytes: Option<i64>,
}
impl Prelude {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.codec.unwrap_or(0), 0 | 1),
            "unsupported FSAR codec"
        );
        ensure!(
            self.entries
                .is_some_and(|v| (1..=MAX_ENTRIES as i32).contains(&v)),
            "invalid FSAR entry count"
        );
        ensure!(
            self.file_bytes
                .is_some_and(|v| (0..=MAX_PAYLOAD as i64).contains(&v)),
            "invalid FSAR file bytes"
        );
        ensure!(
            self.frame_bytes
                .is_some_and(|v| (4..=MAX_FRAMES as i64).contains(&v)),
            "invalid FSAR frame bytes"
        );
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = self.encode_to_vec();
        let mut prelude = b"FSAR\x02".to_vec();
        prelude.extend((bytes.len() as u32).to_be_bytes());
        prelude.extend(bytes);
        Ok(prelude)
    }
}
#[derive(Clone, PartialEq, Message)]
struct Header {
    #[prost(string, optional, tag = "1")]
    path: Option<String>,
    #[prost(int32, optional, tag = "2")]
    kind: Option<i32>,
    #[prost(int64, optional, tag = "3")]
    size: Option<i64>,
    #[prost(int64, optional, tag = "4")]
    modified: Option<i64>,
    #[prost(bool, optional, tag = "5")]
    hidden: Option<bool>,
    #[prost(string, optional, tag = "6")]
    mime: Option<String>,
}
impl Header {
    fn validate(&mut self) -> Result<()> {
        self.path = Some(relative(
            self.path.as_deref().context("missing FSAR path")?,
        )?);
        let size = self.size.context("missing FSAR entry size")?;
        ensure!(
            size >= 0 && size <= MAX_PAYLOAD as i64,
            "invalid FSAR entry size"
        );
        ensure!(
            matches!(self.kind, Some(1) | Some(2)),
            "unknown FSAR entry kind"
        );
        ensure!(
            self.kind != Some(2) || size == 0,
            "FSAR directory must be empty"
        );
        Ok(())
    }
}
pub fn relative(path: &str) -> Result<String> {
    ensure!(
        !path.starts_with(['/', '\\']) && !path.contains('\\'),
        "invalid FSAR relative path"
    );
    let normalized = path.trim().trim_matches('/');
    ensure!(!normalized.is_empty(), "empty FSAR path");
    for part in normalized.split('/') {
        ensure!(
            !part.trim().is_empty() && !matches!(part, "." | ".."),
            "invalid FSAR relative path"
        );
        ensure!(
            matches!(
                Path::new(part).components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            ),
            "invalid FSAR path component"
        );
    }
    Ok(normalized.into())
}
fn plan(request: &ReadRequest) -> Result<(Prelude, Vec<Vec<u8>>)> {
    ensure!(
        (1..=MAX_ENTRIES).contains(&request.entries.len()),
        "invalid FSAR entry count"
    );
    ensure!(
        matches!(request.options.codec, 0 | 1),
        "unsupported FSAR codec"
    );
    let mut paths = HashSet::new();
    let mut headers = vec![];
    let mut file_bytes = 0u64;
    let mut frame_bytes = 4u64;
    for entry in &request.entries {
        ensure!(
            !entry.source_path.trim().is_empty(),
            "empty FSAR source path"
        );
        let path = relative(&entry.relative_path)?;
        ensure!(paths.insert(path.clone()), "duplicate FSAR entry");
        let size = if entry.directory { 0 } else { entry.size };
        ensure!(
            size <= 1024 * 1024,
            "FSAR file exceeds small-file threshold"
        );
        file_bytes = file_bytes.checked_add(size).context("FSAR size overflow")?;
        ensure!(file_bytes <= MAX_PAYLOAD, "FSAR payload too large");
        let header = Header {
            path: Some(path),
            kind: Some(if entry.directory { 2 } else { 1 }),
            size: Some(size as i64),
            modified: (entry.modified_time_millis != 0).then_some(entry.modified_time_millis),
            hidden: entry.hidden.then_some(true),
            mime: (!entry.mime_type.is_empty()).then(|| entry.mime_type.clone()),
        }
        .encode_to_vec();
        ensure!(header.len() <= MAX_HEADER, "FSAR header too large");
        frame_bytes += 4 + header.len() as u64 + size;
        ensure!(frame_bytes <= MAX_FRAMES, "FSAR frames too large");
        headers.push(header);
    }
    Ok((
        Prelude {
            codec: (request.options.codec != 0).then_some(request.options.codec),
            entries: Some(request.entries.len() as i32),
            file_bytes: Some(file_bytes as i64),
            frame_bytes: Some(frame_bytes as i64),
        },
        headers,
    ))
}
pub fn validate_read(request: &ReadRequest, session: &Session, files: &FilePolicy) -> Result<()> {
    plan(request)?;
    for entry in &request.entries {
        if !entry.directory {
            files.check(Path::new(&entry.source_path), session)?;
        }
    }
    Ok(())
}
pub fn validate_write(request: &WriteRequest, session: &Session, files: &FilePolicy) -> Result<()> {
    ensure!(
        (1..=MAX_ENTRIES).contains(&request.expected_entries)
            && request.expected_file_bytes <= MAX_PAYLOAD,
        "invalid FSAR receive plan"
    );
    files.check_write(Path::new(&request.destination_root_path), session)
}
pub struct Reader {
    input: mpsc::Receiver<Result<Vec<u8>>>,
    pending: Bytes,
    credit: Option<(Arc<Transport>, i32)>,
    seen: u64,
    max: u64,
}
impl Reader {
    fn new(
        input: mpsc::Receiver<Result<Vec<u8>>>,
        credit: Option<(Arc<Transport>, i32)>,
        max: u64,
    ) -> Self {
        Self {
            input,
            pending: Bytes::new(),
            credit,
            seen: 0,
            max,
        }
    }
    async fn fill(&mut self) -> Result<bool> {
        while self.pending.is_empty() {
            let Some(bytes) = self.input.recv().await else {
                return Ok(false);
            };
            let bytes: Vec<u8> = bytes?;
            self.seen = self
                .seen
                .checked_add(bytes.len() as u64)
                .context("FSAR size overflow")?;
            ensure!(self.seen <= self.max, "FSAR stream exceeds byte limit");
            if let Some((transport, stream)) = &self.credit {
                transport.window(*stream, bytes.len()).await?;
            }
            self.pending = bytes.into();
        }
        Ok(true)
    }
    async fn exact(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        while result.len() < size {
            ensure!(self.fill().await?, "truncated FSAR stream");
            let count = (size - result.len()).min(self.pending.len());
            result.extend(self.pending.split_to(count));
        }
        Ok(result)
    }
    async fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.fill().await? {
            return Ok(None);
        }
        Ok(Some(std::mem::take(&mut self.pending).to_vec()))
    }
    async fn prelude(&mut self) -> Result<(Prelude, Vec<u8>)> {
        let mut wire = self.exact(9).await?;
        ensure!(&wire[..5] == b"FSAR\x02", "invalid FSAR magic/version");
        let length = u32::from_be_bytes(wire[5..9].try_into()?) as usize;
        ensure!(
            (1..=MAX_HEADER).contains(&length),
            "invalid FSAR prelude length"
        );
        let header = self.exact(length).await?;
        let prelude = Prelude::decode(header.as_slice())?;
        prelude.validate()?;
        wire.extend(header);
        Ok((prelude, wire))
    }
}
async fn pipe(
    codec: i32,
    decompress: bool,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: &mpsc::Sender<Result<Vec<u8>>>,
) -> Result<()> {
    match codec {
        0 => {
            while let Some(bytes) = input.recv().await {
                output.send(Ok(bytes)).await.context("FSAR output closed")?;
            }
            Ok(())
        }
        1 if decompress => {
            let mut op = zstd::stream::raw::Decoder::new()?;
            op.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(27))?;
            crate::management::compression::transform(op, true, input, output).await
        }
        1 => {
            crate::management::compression::transform(
                zstd::stream::raw::Encoder::new(1)?,
                false,
                input,
                output,
            )
            .await
        }
        _ => anyhow::bail!("unsupported FSAR codec"),
    }
}
pub(crate) async fn send(
    t: &Transfer,
    session: &Session,
    files: &FilePolicy,
    request: &ReadRequest,
) -> Result<TransferResult> {
    let (prelude, headers) = plan(request)?;
    t.transport.data(t.stream(), &prelude.encode()?).await?;
    let (tx, input) = mpsc::channel(1);
    let (output, mut rx) = mpsc::channel::<Result<Vec<u8>>>(1);
    let producer = async {
        for (entry, header) in request.entries.iter().zip(headers) {
            tx.send((header.len() as u32).to_be_bytes().to_vec())
                .await?;
            tx.send(header).await?;
            if !entry.directory {
                let mut file = files
                    .open(Path::new(&entry.source_path), session, false, false, false)?
                    .into_std();
                ensure!(
                    file.metadata()?.len() == entry.size,
                    "archive source changed while planning"
                );
                let mut remaining = entry.size;
                let mut buffer = vec![0; 64 * 1024];
                while remaining > 0 {
                    t.running().await?;
                    let size = remaining.min(buffer.len() as u64) as usize;
                    file.read_exact(&mut buffer[..size])?;
                    tx.send(buffer[..size].to_vec()).await?;
                    remaining -= size as u64;
                    t.progress(&entry.relative_path, size);
                }
            }
        }
        tx.send(vec![0; 4]).await?;
        drop(tx);
        Ok::<(), anyhow::Error>(())
    };
    let consumer = async {
        while let Some(bytes) = rx.recv().await {
            t.running().await?;
            let bytes: Vec<u8> = bytes?;
            t.transport.data(t.stream(), &bytes).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let codec = async {
        let result = pipe(request.options.codec, false, input, &output).await;
        drop(output);
        result
    };
    tokio::try_join!(producer, codec, consumer)?;
    Ok(TransferResult {
        completed_relative_paths: request
            .entries
            .iter()
            .map(|e| e.relative_path.clone())
            .collect(),
        committed_file_bytes: prelude.file_bytes.unwrap() as u64,
    })
}
async fn frames(
    t: &Transfer,
    session: &Session,
    files: &FilePolicy,
    mut reader: Reader,
    header: &Prelude,
    request: &WriteRequest,
) -> Result<TransferResult> {
    let mut count = 0usize;
    let mut frame_bytes = 0u64;
    let mut file_bytes = 0u64;
    let mut paths = HashSet::new();
    let mut result = TransferResult::default();
    loop {
        let size = u32::from_be_bytes(reader.exact(4).await?.as_slice().try_into()?) as usize;
        frame_bytes += 4;
        if size == 0 {
            ensure!(reader.next().await?.is_none(), "trailing FSAR data");
            ensure!(
                count == header.entries.unwrap() as usize
                    && file_bytes == header.file_bytes.unwrap() as u64
                    && frame_bytes == header.frame_bytes.unwrap() as u64,
                "FSAR prelude does not match entries"
            );
            ensure!(
                count == request.expected_entries
                    && result.committed_file_bytes == request.expected_file_bytes,
                "FSAR committed entries do not match request"
            );
            return Ok(result);
        }
        ensure!(
            (1..=MAX_HEADER).contains(&size),
            "invalid FSAR header length"
        );
        count += 1;
        ensure!(count <= MAX_ENTRIES, "too many FSAR entries");
        let mut entry = Header::decode(reader.exact(size).await?.as_slice())?;
        entry.validate()?;
        let path = entry.path.as_ref().unwrap();
        ensure!(paths.insert(path.clone()), "duplicate FSAR entry");
        let length = entry.size.unwrap() as u64;
        ensure!(
            length <= 1024 * 1024,
            "FSAR entry exceeds small-file threshold"
        );
        file_bytes += length;
        frame_bytes += size as u64 + length;
        ensure!(
            file_bytes <= header.file_bytes.unwrap() as u64
                && frame_bytes <= header.frame_bytes.unwrap() as u64,
            "FSAR entries exceed prelude"
        );
        let root = Path::new(&request.destination_root_path);
        let target = root.join(path);
        t.prepare(session, files, &target, length, entry.kind == Some(2))
            .await?;
        if entry.kind == Some(2) {
            files.make_directory(&target, session)?;
        } else {
            let mut target = files.receive_target(&target, session)?;
            if length == 0 {
                target.file.set_len(0)?;
            } else if target.file.metadata()?.len() < length {
                target.file.set_len(length)?;
            }
            let mut remaining = length;
            while remaining > 0 {
                t.running().await?;
                let bytes = reader.exact(remaining.min(64 * 1024) as usize).await?;
                target.file.write_all(&bytes)?;
                remaining -= bytes.len() as u64;
                t.progress(path, bytes.len());
            }
            target.file.flush()?;
            target.commit();
        }
        result.completed_relative_paths.push(path.clone());
        result.committed_file_bytes += length;
        t.committed(result.clone());
    }
}
pub(crate) async fn receive(
    t: &Transfer,
    session: &Session,
    files: &FilePolicy,
    input: mpsc::Receiver<Result<Vec<u8>>>,
    request: &WriteRequest,
) -> Result<TransferResult> {
    t.running().await?;
    let mut raw = Reader::new(
        input,
        Some((t.transport.clone(), t.stream())),
        MAX_FRAMES + MAX_HEADER as u64,
    );
    let (header, _) = raw.prelude().await?;
    let (tx, input) = mpsc::channel(1);
    let (output, rx) = mpsc::channel(1);
    let feeder = async {
        while let Some(bytes) = raw.next().await? {
            t.running().await?;
            tx.send(bytes).await?;
        }
        drop(tx);
        Ok::<(), anyhow::Error>(())
    };
    let codec = async {
        let result = pipe(header.codec.unwrap_or(0), true, input, &output).await;
        drop(output);
        result
    };
    let decoder = frames(
        t,
        session,
        files,
        Reader::new(rx, None, header.frame_bytes.unwrap() as u64),
        &header,
        request,
    );
    let (_, _, result) = tokio::try_join!(feeder, codec, decoder)?;
    Ok(result)
}
pub(crate) async fn relay(
    t: &Transfer,
    target: &Transport,
    stream: i32,
    input: mpsc::Receiver<Result<Vec<u8>>>,
    options: &Options,
) -> Result<TransferResult> {
    t.running().await?;
    let mut raw = Reader::new(
        input,
        Some((t.transport.clone(), t.stream())),
        MAX_FRAMES + MAX_HEADER as u64,
    );
    let (header, prelude) = raw.prelude().await?;
    ensure!(
        header.codec.unwrap_or(0) == options.codec,
        "archive relay codec mismatch"
    );
    let mut sent = prelude.len() as u64;
    target.data(stream, &prelude).await?;
    while let Some(bytes) = raw.next().await? {
        t.running().await?;
        target.data(stream, &bytes).await?;
        sent += bytes.len() as u64;
    }
    Ok(TransferResult {
        completed_relative_paths: vec![],
        committed_file_bytes: sent,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protobuf_prelude_and_paths_match_frozen_fsar_v2() {
        let header = Prelude {
            codec: None,
            entries: Some(1),
            file_bytes: Some(0),
            frame_bytes: Some(4),
        };
        assert_eq!(
            header.encode().unwrap(),
            vec![70, 83, 65, 82, 2, 0, 0, 0, 6, 16, 1, 24, 0, 32, 4]
        );
        assert!(
            Prelude::decode(&[16, 1, 32, 4][..])
                .unwrap()
                .validate()
                .is_err()
        );
        for path in [
            "../escape",
            "/absolute",
            "a\\b",
            "a//b",
            "a/../b",
            "a/./b",
            "",
        ] {
            assert!(relative(path).is_err(), "{path}");
        }
        assert_eq!(relative("  目录/文件 .txt/ ").unwrap(), "目录/文件 .txt");
        assert!(
            Header {
                path: Some("x".into()),
                kind: Some(2),
                size: Some(1),
                modified: None,
                hidden: None,
                mime: None
            }
            .validate()
            .is_err()
        );
    }
}
