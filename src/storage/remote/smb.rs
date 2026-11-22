use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::{DownloadPart, Entry, endpoint, safe_segment},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use smb2::{
    Frame, Session, Tree,
    client::connection::Connection,
    msg::{
        close::{CloseRequest, CloseResponse},
        create::{
            CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
        },
        flush::{FlushRequest, FlushResponse},
        query_directory::{
            FileInformationClass, QueryDirectoryFlags, QueryDirectoryRequest,
            QueryDirectoryResponse,
        },
        read::{ReadRequest, ReadResponse},
        set_info::{SetInfoRequest, SetInfoResponse},
        write::{WriteRequest, WriteResponse},
    },
    pack::{Pack, ReadCursor, Unpack},
    types::{Command, FileId, OplockLevel, flags::FileAccessMask, status::NtStatus},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroize;

const DIRECTORY: u32 = 0x10;
const REPARSE: u32 = 0x400;
const OPEN_REPARSE: u32 = 0x20_0000;
const READ: u32 = 0x8000_0000;
const WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x1_0000;
const ATTRIBUTES: u32 = 0x80;
const NAME_NOT_FOUND: u32 = 0xc000_0034;
const STOPPED_ON_SYMLINK: u32 = 0x8000_002d;

#[derive(Default, Deserialize)]
#[serde(default)]
struct Extras {
    share: String,
    domain: String,
}
struct Credentials {
    username: String,
    password: String,
    extras: Extras,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Clone)]
pub struct Smb {
    host: String,
    separator: String,
    auth: Arc<Credentials>,
}
struct ConnectionGuard(Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.mark_dead();
    }
}
struct Share {
    guard: ConnectionGuard,
    tree: Tree,
}

fn authority() -> anyhow::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "remote reparse point or unsafe parent",
    )
    .into()
}
fn success(frame: &Frame) -> Result<()> {
    if frame.header.status.0 == STOPPED_ON_SYMLINK {
        return Err(authority());
    }
    ensure!(frame.header.status == NtStatus::SUCCESS, PlatformFailure);
    Ok(())
}
fn decode<T: Unpack>(frame: &Frame) -> Result<T> {
    success(frame)?;
    T::unpack(&mut ReadCursor::new(&frame.body)).map_err(|_| PlatformFailure.into())
}
fn normalize(path: &str) -> Result<String> {
    if path.trim().is_empty() {
        return Ok(String::new());
    }
    let path = path.replace('/', "\\");
    let path = path.trim_matches('\\');
    ensure!(
        path.is_empty() || (path.split('\\').count() <= 256 && path.split('\\').all(safe_segment)),
        "invalid SMB path"
    );
    Ok(path.into())
}
fn timestamp(ticks: u64) -> i64 {
    ((ticks as i128 - 116_444_736_000_000_000) / 10_000) as i64
}
fn directory_entries(bytes: &[u8], base: &str, separator: &str) -> Result<Vec<Entry>> {
    let mut entries = vec![];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let record = bytes
            .get(offset..)
            .filter(|s| s.len() >= 64)
            .context(PlatformFailure)?;
        let u32_at = |i| u32::from_le_bytes(record[i..i + 4].try_into().unwrap());
        let u64_at = |i| u64::from_le_bytes(record[i..i + 8].try_into().unwrap());
        let next = u32_at(0) as usize;
        let length = u32_at(60) as usize;
        ensure!(
            length % 2 == 0 && length <= record.len() - 64,
            PlatformFailure
        );
        let name = String::from_utf16(
            &record[64..64 + length]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| PlatformFailure)?;
        if safe_segment(&name) {
            let attributes = u32_at(56);
            let directory = attributes & DIRECTORY != 0;
            let date = timestamp(u64_at(24));
            let prefix = if base.ends_with(separator) {
                base.to_owned()
            } else {
                format!("{base}{separator}")
            };
            entries.push(Entry {
                path: format!("{prefix}{name}"),
                name,
                is_directory: directory,
                size: if directory {
                    -1
                } else {
                    i64::try_from(u64_at(40)).map_err(|_| PlatformFailure)?
                },
                created_date: date,
                updated_date: date,
                is_hidden: attributes & 2 != 0,
                is_symbolic_link: attributes & REPARSE != 0,
                is_symbolic_link_known: true,
                reference: None,
            });
        }
        if next == 0 {
            break;
        }
        ensure!(
            next >= 64 + length && next % 8 == 0 && next < record.len(),
            PlatformFailure
        );
        offset += next;
    }
    Ok(entries)
}
impl Share {
    async fn frame(&self, command: Command, request: &dyn Pack) -> Result<Frame> {
        let frame = self
            .guard
            .0
            .execute(command, request, Some(self.tree.tree_id))
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(
            frame.header.command == command && frame.body.len() <= 256 * 1024,
            PlatformFailure
        );
        Ok(frame)
    }
    async fn raw_open(
        &self,
        path: &str,
        access: u32,
        disposition: CreateDisposition,
        options: u32,
    ) -> Result<Frame> {
        self.frame(
            Command::Create,
            &CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                desired_access: FileAccessMask::new(access),
                file_attributes: if options & 1 != 0 { DIRECTORY } else { 0 },
                share_access: ShareAccess(7),
                create_disposition: disposition,
                create_options: options | OPEN_REPARSE,
                name: path.into(),
                create_contexts: vec![],
            },
        )
        .await
    }
    async fn close(&self, id: FileId) -> Result<()> {
        let _: CloseResponse = decode(
            &self
                .frame(
                    Command::Close,
                    &CloseRequest {
                        flags: 0,
                        file_id: id,
                    },
                )
                .await?,
        )?;
        Ok(())
    }
    async fn checked(&self, path: &str, missing_leaf: bool) -> Result<()> {
        let parts = if path.is_empty() {
            vec![]
        } else {
            path.split('\\').collect::<Vec<_>>()
        };
        for count in 0..=parts.len() {
            let prefix = parts[..count].join("\\");
            let frame = self
                .raw_open(&prefix, ATTRIBUTES, CreateDisposition::FileOpen, 0)
                .await?;
            if missing_leaf && count == parts.len() && frame.header.status.0 == NAME_NOT_FOUND {
                return Ok(());
            }
            let info: CreateResponse = decode(&frame)?;
            self.close(info.file_id).await?;
            ensure!(
                info.file_attributes & REPARSE == 0
                    && (count == parts.len() || info.file_attributes & DIRECTORY != 0),
                authority()
            );
        }
        Ok(())
    }
    async fn open(
        &self,
        path: &str,
        access: u32,
        disposition: CreateDisposition,
        options: u32,
        missing: bool,
    ) -> Result<CreateResponse> {
        self.checked(path, missing).await?;
        let info: CreateResponse =
            decode(&self.raw_open(path, access, disposition, options).await?)?;
        ensure!(info.file_attributes & REPARSE == 0, authority());
        Ok(info)
    }
    async fn list(&self, path: &str, display: &str, separator: &str) -> Result<Vec<Entry>> {
        let opened = self
            .open(path, READ, CreateDisposition::FileOpen, 1, false)
            .await?;
        let mut entries = vec![];
        let mut total = 0usize;
        let mut restart = true;
        loop {
            let frame = self
                .frame(
                    Command::QueryDirectory,
                    &QueryDirectoryRequest {
                        file_information_class: FileInformationClass::FileDirectoryInformation,
                        flags: QueryDirectoryFlags(if restart {
                            QueryDirectoryFlags::RESTART_SCANS
                        } else {
                            0
                        }),
                        file_index: 0,
                        file_id: opened.file_id,
                        output_buffer_length: 64 * 1024,
                        file_name: "*".into(),
                    },
                )
                .await?;
            if frame.header.status == NtStatus::NO_MORE_FILES {
                break;
            }
            let response: QueryDirectoryResponse = decode(&frame)?;
            ensure!(
                !response.output_buffer.is_empty() && response.output_buffer.len() <= 64 * 1024,
                PlatformFailure
            );
            total += response.output_buffer.len();
            ensure!(
                total <= 8 * 1024 * 1024,
                ResourceUnavailable("SMB directory exceeds byte limit")
            );
            entries.extend(directory_entries(
                &response.output_buffer,
                display,
                separator,
            )?);
            ensure!(
                entries.len() <= 100_000,
                ResourceUnavailable("SMB directory exceeds entry limit")
            );
            restart = false;
        }
        self.close(opened.file_id).await?;
        Ok(entries)
    }
    async fn set_info(&self, file_id: FileId, class: u8, buffer: Vec<u8>) -> Result<()> {
        let _: SetInfoResponse = decode(
            &self
                .frame(
                    Command::SetInfo,
                    &SetInfoRequest {
                        info_type: smb2::msg::query_info::InfoType::File,
                        file_info_class: class,
                        additional_information: 0,
                        file_id,
                        buffer,
                    },
                )
                .await?,
        )?;
        Ok(())
    }
    async fn flush(&self, file_id: FileId) -> Result<()> {
        let _: FlushResponse = decode(
            &self
                .frame(Command::Flush, &FlushRequest { file_id })
                .await?,
        )?;
        Ok(())
    }
    async fn remove(&self, path: &str, directory: bool) -> Result<()> {
        let opened = self
            .open(
                path,
                DELETE,
                CreateDisposition::FileOpen,
                if directory { 1 } else { 0x40 },
                false,
            )
            .await?;
        self.set_info(opened.file_id, 13, vec![1]).await?;
        self.close(opened.file_id).await
    }
}
impl Smb {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        separator: &str,
        extras: &serde_json::Value,
    ) -> Result<Self> {
        let extras: Extras =
            serde_json::from_value(extras.get("smb").cloned().unwrap_or(serde_json::json!({})))?;
        Ok(Self {
            host: host.into(),
            separator: if separator.is_empty() {
                "/".into()
            } else {
                separator.into()
            },
            auth: Arc::new(Credentials {
                username: username.into(),
                password: password.into(),
                extras,
            }),
        })
    }
    async fn connect(&self) -> Result<Share> {
        ensure!(
            !self.auth.extras.share.trim().is_empty(),
            ResourceUnavailable("SMB share name required")
        );
        ensure!(safe_segment(&self.auth.extras.share), PlatformFailure);
        let (host, port) = endpoint(&self.host, 445)?;
        let address = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut guard = ConnectionGuard(
            Connection::connect(&address, Duration::from_secs(10))
                .await
                .map_err(|_| PlatformFailure)?,
        );
        guard.0.set_response_timeout(Some(Duration::from_secs(300)));
        guard.0.set_send_timeout(Some(Duration::from_secs(300)));
        guard.0.negotiate().await.map_err(|_| PlatformFailure)?;
        let session = Session::setup(
            &mut guard.0,
            &self.auth.username,
            &self.auth.password,
            &self.auth.extras.domain,
        )
        .await
        .map_err(|_| PlatformFailure)?;
        ensure!(
            session.should_sign && !session.signing_key.is_empty(),
            PlatformFailure
        );
        let tree = Tree::connect(&mut guard.0, &self.auth.extras.share)
            .await
            .map_err(|_| PlatformFailure)?;
        ensure!(!tree.is_dfs, PlatformFailure);
        if tree.encrypt_data && !guard.0.should_encrypt() {
            let params = guard.0.params().context(PlatformFailure)?;
            guard.0.activate_encryption(
                session.encryption_key.clone().context(PlatformFailure)?,
                session.decryption_key.clone().context(PlatformFailure)?,
                params.cipher.unwrap_or(smb2::client::Cipher::Aes128Ccm),
            );
        }
        Ok(Share { guard, tree })
    }
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let normalized = normalize(path)?;
        self.connect()
            .await?
            .list(&normalized, path, &self.separator)
            .await
    }
    pub async fn download(
        &self,
        path: &str,
        size: i64,
        output: &mpsc::Sender<DownloadPart>,
    ) -> Result<()> {
        let path = normalize(path)?;
        let share = self.connect().await?;
        let opened = share
            .open(&path, READ, CreateDisposition::FileOpen, 0x40, false)
            .await?;
        let mut offset = 0u64;
        let max = share
            .guard
            .0
            .params()
            .context(PlatformFailure)?
            .max_read_size
            .min(64 * 1024);
        ensure!(max > 0, PlatformFailure);
        loop {
            let frame = share
                .frame(
                    Command::Read,
                    &ReadRequest {
                        padding: 0,
                        flags: 0,
                        length: max,
                        offset,
                        file_id: opened.file_id,
                        minimum_count: 1,
                        channel: 0,
                        remaining_bytes: 0,
                        read_channel_info: vec![],
                    },
                )
                .await?;
            if frame.header.status == NtStatus::END_OF_FILE {
                break;
            }
            let response: ReadResponse = decode(&frame)?;
            ensure!(
                !response.data.is_empty() && response.data.len() <= max as usize,
                PlatformFailure
            );
            offset = offset
                .checked_add(response.data.len() as u64)
                .context(PlatformFailure)?;
            output
                .send(Ok((response.data, size.max(0))))
                .await
                .map_err(|_| PlatformFailure)?;
        }
        share.close(opened.file_id).await
    }
    pub async fn upload(
        &self,
        path: &str,
        size: i64,
        mut input: mpsc::Receiver<Vec<u8>>,
        consumed: Arc<AtomicU64>,
    ) -> Result<bool> {
        let path = normalize(path)?;
        ensure!(!path.is_empty(), "SMB object required");
        let share = self.connect().await?;
        let opened = share
            .open(&path, WRITE, CreateDisposition::FileOverwriteIf, 0x40, true)
            .await?;
        let max = share
            .guard
            .0
            .params()
            .context(PlatformFailure)?
            .max_write_size
            .min(64 * 1024) as usize;
        ensure!(max > 0, PlatformFailure);
        let mut offset = 0u64;
        while let Some(bytes) = input.recv().await {
            for chunk in bytes.chunks(max) {
                let next = offset
                    .checked_add(chunk.len() as u64)
                    .context(PlatformFailure)?;
                ensure!(
                    size < 0 || next <= size as u64,
                    ResourceUnavailable("upload length exceeded")
                );
                let frame = share
                    .frame(
                        Command::Write,
                        &WriteRequest {
                            data_offset: 112,
                            offset,
                            file_id: opened.file_id,
                            channel: 0,
                            remaining_bytes: 0,
                            write_channel_info_offset: 0,
                            write_channel_info_length: 0,
                            flags: 0,
                            data: chunk.to_vec(),
                        },
                    )
                    .await?;
                let response: WriteResponse = decode(&frame)?;
                ensure!(response.count as usize == chunk.len(), PlatformFailure);
                offset = next;
                consumed.store(offset, Ordering::Release);
            }
        }
        ensure!(
            size < 0 || offset == size as u64,
            ResourceUnavailable("upload length mismatch")
        );
        share.flush(opened.file_id).await?;
        share.close(opened.file_id).await?;
        Ok(true)
    }
    pub async fn mutate(
        &self,
        operation: &str,
        path: &str,
        destination: &str,
        directory: bool,
    ) -> Result<bool> {
        let from = normalize(path)?;
        ensure!(!from.is_empty(), "cannot mutate SMB share root");
        let to = if matches!(operation, "/rename" | "/move" | "/copy") {
            Some(normalize(destination)?)
        } else {
            None
        };
        if let Some(to) = &to {
            ensure!(!to.is_empty(), "SMB destination required");
        }
        if operation == "/move" {
            let to = to.as_ref().unwrap();
            ensure!(
                from != *to && !to.starts_with(&format!("{from}\\")),
                "invalid move destination"
            );
        }
        let mut share = self.connect().await?;
        match operation {
            "/create" | "/mkdir" => {
                let opened = share
                    .open(
                        &from,
                        WRITE,
                        if operation == "/mkdir" {
                            CreateDisposition::FileCreate
                        } else {
                            CreateDisposition::FileOverwriteIf
                        },
                        if operation == "/mkdir" { 1 } else { 0x40 },
                        true,
                    )
                    .await?;
                share.close(opened.file_id).await?;
            }
            "/delete" | "/delete-empty-directory" => {
                if directory && operation == "/delete" {
                    let mut pending = vec![from.clone()];
                    let mut dirs = vec![];
                    let mut count = 0;
                    while let Some(dir) = pending.pop() {
                        let entries = share.list(&dir, &dir, "\\").await?;
                        for entry in entries {
                            count += 1;
                            ensure!(
                                count <= 100_000,
                                ResourceUnavailable("SMB tree exceeds entry limit")
                            );
                            if entry.is_directory {
                                pending.push(entry.path);
                            } else {
                                share.remove(&entry.path, false).await?;
                            }
                        }
                        dirs.push(dir);
                    }
                    for dir in dirs.into_iter().rev() {
                        share.remove(&dir, true).await?;
                    }
                } else {
                    share
                        .remove(&from, directory || operation == "/delete-empty-directory")
                        .await?;
                }
            }
            "/rename" | "/move" => {
                let to = to.as_ref().unwrap();
                if operation == "/move" {
                    let (parent, name) = to.rsplit_once('\\').unwrap_or(("", to));
                    let entries = share.list(parent, parent, "\\").await.map_err(|_| {
                        ResourceUnavailable("cannot verify move destination is absent")
                    })?;
                    ensure!(
                        !entries.iter().any(|e| e.name == name),
                        ResourceUnavailable("move target already exists")
                    );
                }
                share.checked(to, true).await?;
                let opened = share
                    .open(&from, DELETE | WRITE, CreateDisposition::FileOpen, 0, false)
                    .await?;
                let name = to
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                let mut buffer = vec![0; 16];
                buffer.extend(u32::try_from(name.len())?.to_le_bytes());
                buffer.extend(name);
                share.set_info(opened.file_id, 10, buffer).await?;
                share.close(opened.file_id).await?;
            }
            "/copy" => {
                let source = share
                    .open(&from, READ, CreateDisposition::FileOpen, 0x40, false)
                    .await?;
                let target = share
                    .open(
                        to.as_ref().unwrap(),
                        READ | WRITE,
                        CreateDisposition::FileOverwriteIf,
                        0x40,
                        true,
                    )
                    .await?;
                let key = share
                    .tree
                    .request_resume_key(&mut share.guard.0, source.file_id)
                    .await
                    .map_err(|_| PlatformFailure)?;
                let count = share
                    .tree
                    .server_side_copy_range(
                        &mut share.guard.0,
                        target.file_id,
                        &key,
                        0,
                        0,
                        source.end_of_file,
                    )
                    .await
                    .map_err(|_| PlatformFailure)?;
                ensure!(count == source.end_of_file, PlatformFailure);
                share.flush(target.file_id).await?;
                share.close(source.file_id).await?;
                share.close(target.file_id).await?;
            }
            _ => return Err(PlatformFailure.into()),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smb_names_and_directory_records_are_strict_and_literal() {
        assert_eq!(normalize("/a/中文 %.txt ").unwrap(), "a\\中文 %.txt ");
        for path in ["/a/../b", "/a//b", "/a/./b", "/a\0b"] {
            assert!(normalize(path).is_err());
        }
        let name = "中文 ?%.txt "
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut record = vec![0u8; 64];
        record[24..32].copy_from_slice(&132_223_104_000_000_000u64.to_le_bytes());
        record[40..48].copy_from_slice(&5u64.to_le_bytes());
        record[56..60].copy_from_slice(&(2 | REPARSE).to_le_bytes());
        record[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
        record.extend(name);
        let parsed = directory_entries(&record, "/", "/").unwrap();
        assert_eq!(parsed[0].name, "中文 ?%.txt ");
        assert_eq!(parsed[0].updated_date, 1577836800000);
        assert!(parsed[0].is_hidden && parsed[0].is_symbolic_link);
        assert_eq!(parsed[0].size, 5);
        record[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(directory_entries(&record, "/", "/").is_err());
        record[0..4].copy_from_slice(&0u32.to_le_bytes());
        record.pop();
        assert!(directory_entries(&record, "/", "/").is_err());
    }
    #[tokio::test]
    async fn smb_reparse_parents_fail_before_the_leaf_and_cancel_wakes_waiters() {
        use smb2::{
            msg::{create::CreateAction, header::Header, negotiate::NegotiateResponse},
            pack::{FileTime, Guid, WriteCursor},
            transport::MockTransport,
            types::{
                Dialect, TreeId,
                flags::{Capabilities, SecurityMode},
            },
        };
        fn packet(command: Command, body: &dyn Pack) -> Vec<u8> {
            let mut header = Header::new_request(command);
            header.flags.set_response();
            header.credits = 32;
            if command != Command::Negotiate {
                header.tree_id = Some(TreeId(1));
            }
            let mut cursor = WriteCursor::new();
            header.pack(&mut cursor);
            body.pack(&mut cursor);
            cursor.into_inner()
        }
        fn opened(attributes: u32) -> CreateResponse {
            CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::FileOpened,
                creation_time: FileTime::ZERO,
                last_access_time: FileTime::ZERO,
                last_write_time: FileTime::ZERO,
                change_time: FileTime::ZERO,
                allocation_size: 0,
                end_of_file: 0,
                file_attributes: attributes,
                file_id: FileId {
                    persistent: 1,
                    volatile: 1,
                },
                create_contexts: vec![],
            }
        }
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        mock.queue_response(packet(
            Command::Negotiate,
            &NegotiateResponse {
                security_mode: SecurityMode::new(1),
                dialect_revision: Dialect::Smb2_0_2,
                server_guid: Guid::ZERO,
                capabilities: Capabilities::default(),
                max_transact_size: 65536,
                max_read_size: 65536,
                max_write_size: 65536,
                system_time: 0,
                server_start_time: 0,
                security_buffer: vec![],
                negotiate_contexts: vec![],
            },
        ));
        let mut conn =
            Connection::from_transport(Box::new(mock.clone()), Box::new(mock.clone()), "fixture");
        conn.negotiate().await.unwrap();
        mock.queue_response(packet(
            Command::TreeConnect,
            &smb2::msg::tree_connect::TreeConnectResponse {
                share_type: smb2::msg::tree_connect::ShareType::Disk,
                share_flags: smb2::types::flags::ShareFlags::default(),
                capabilities: smb2::types::flags::ShareCapabilities::default(),
                maximal_access: u32::MAX,
            },
        ));
        let tree = Tree::connect(&mut conn, "fixture").await.unwrap();
        let close = CloseResponse {
            flags: 0,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        };
        mock.queue_responses(vec![
            packet(Command::Create, &opened(DIRECTORY)),
            packet(Command::Close, &close),
            packet(Command::Create, &opened(DIRECTORY | REPARSE)),
            packet(Command::Close, &close),
        ]);
        let share = Share {
            guard: ConnectionGuard(conn),
            tree,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            share.checked("parent\\never-opened", false),
        )
        .await
        .unwrap();
        assert_eq!(
            crate::management::reply::Reply::from_error(result.unwrap_err()).status,
            403
        );
        let creates = mock
            .sent_messages()
            .into_iter()
            .filter_map(|bytes| {
                let header = Header::unpack(&mut ReadCursor::new(&bytes)).unwrap();
                (header.command == Command::Create)
                    .then(|| CreateRequest::unpack(&mut ReadCursor::new(&bytes[64..])).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            creates.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["", "parent"]
        );
        assert!(creates.iter().all(|r| r.create_options & OPEN_REPARSE != 0));
        mock.assert_fully_consumed();
        let connection = share.guard.0.clone();
        let pending = tokio::spawn(async move {
            connection
                .execute(
                    Command::Close,
                    &CloseRequest {
                        flags: 0,
                        file_id: FileId {
                            persistent: 9,
                            volatile: 9,
                        },
                    },
                    Some(TreeId(1)),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!pending.is_finished());
        drop(share);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        mock.close();
    }
}
