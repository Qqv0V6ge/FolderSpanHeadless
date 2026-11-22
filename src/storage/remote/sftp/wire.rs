//! Bounded SFTP v3–v6 codec. Handles and extension values are opaque bytes, never UTF-8 text.
use std::{collections::HashMap, fmt, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
type Stream = russh::ChannelStream<russh::client::Msg>;
const MAX_PACKET: usize = 256 * 1024;
#[derive(Debug)]
pub enum Error {
    Status(Status),
    Malformed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SFTP request failed")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum StatusCode {
    Ok,
    Eof,
    NoSuchFile,
    Other(u32),
}
impl From<u32> for StatusCode {
    fn from(n: u32) -> Self {
        match n {
            0 => Self::Ok,
            1 => Self::Eof,
            2 => Self::NoSuchFile,
            n => Self::Other(n),
        }
    }
}
#[derive(Debug)]
pub struct Status {
    pub status_code: StatusCode,
}
#[derive(Default)]
pub struct FileAttributes {
    kind: Option<u8>,
    pub size: Option<u64>,
    pub permissions: Option<u32>,
    pub mtime: Option<i64>,
}
#[derive(Clone, Copy)]
pub enum FileType {
    File,
    Dir,
    Symlink,
    Other,
}
impl FileType {
    pub fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
    pub fn is_symlink(self) -> bool {
        matches!(self, Self::Symlink)
    }
}
impl FileAttributes {
    pub fn type_known(&self) -> bool {
        self.kind
            .map(|kind| kind != 5)
            .unwrap_or_else(|| self.permissions.is_some_and(|p| p & 0xf000 != 0))
    }
    pub fn file_type(&self) -> FileType {
        if let Some(kind) = self.kind {
            return match kind {
                1 => FileType::File,
                2 => FileType::Dir,
                3 => FileType::Symlink,
                _ => FileType::Other,
            };
        }
        match self.permissions.unwrap_or(0) & 0xf000 {
            0x8000 => FileType::File,
            0x4000 => FileType::Dir,
            0xa000 => FileType::Symlink,
            _ => FileType::Other,
        }
    }
}
#[derive(Clone, Copy)]
pub struct OpenFlags(u32);
impl OpenFlags {
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const CREATE: Self = Self(8);
    pub const TRUNCATE: Self = Self(16);
}
impl std::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
pub struct Handle {
    pub handle: Vec<u8>,
}
pub struct Attrs {
    pub attrs: FileAttributes,
}
pub struct Data {
    pub data: Vec<u8>,
}
pub struct File {
    pub filename: String,
    pub attrs: FileAttributes,
}
pub struct Name {
    pub files: Vec<File>,
    pub end: bool,
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let data = self.0.get(..n).ok_or(Error::Malformed)?;
        self.0 = &self.0[n..];
        Ok(data)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn text(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| Error::Malformed)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
    fn attrs(&mut self, version: u32) -> Result<FileAttributes> {
        let flags = self.u32()?;
        let allowed = match version {
            3 => 0x8000_000f,
            4 | 5 => 0x8000_03fd,
            6 => 0x8000_fffd,
            _ => return Err(Error::Malformed),
        };
        if flags & !allowed != 0 {
            return Err(Error::Malformed);
        }
        let kind = if version >= 4 {
            Some(self.take(1)?[0])
        } else {
            None
        };
        let size = if flags & 1 != 0 {
            Some(self.u64()?)
        } else {
            None
        };
        if version >= 6 && flags & 0x400 != 0 {
            self.u64()?;
        }
        if version == 3 && flags & 2 != 0 {
            self.take(8)?;
        }
        if version >= 4 && flags & 0x80 != 0 {
            self.bytes()?;
            self.bytes()?;
        }
        let mut permissions = if flags & 4 != 0 {
            Some(self.u32()?)
        } else {
            None
        };
        if let Some(kind) = kind {
            let file_mode = match kind {
                1 => 0o100000,
                2 => 0o040000,
                3 => 0o120000,
                6 => 0o140000,
                7 => 0o020000,
                8 => 0o060000,
                9 => 0o010000,
                _ => 0,
            };
            permissions = Some(permissions.unwrap_or(0) | file_mode);
        }
        let mtime = if version == 3 && flags & 8 != 0 {
            self.u32()?;
            Some(i64::from(self.u32()?) * 1000)
        } else {
            for flag in [8, 16] {
                if flags & flag != 0 {
                    self.time(flags)?;
                }
            }
            let modified = if flags & 32 != 0 {
                Some(self.time(flags)?)
            } else {
                None
            };
            if version >= 6 && flags & 0x8000 != 0 {
                self.time(flags)?;
            }
            modified
        };
        if version >= 4 {
            if flags & 0x40 != 0 {
                let mut acl = Reader(self.bytes()?);
                if version >= 6 {
                    acl.u32()?;
                }
                let count = acl.u32()? as usize;
                if count > acl.0.len() / 16 {
                    return Err(Error::Malformed);
                }
                for _ in 0..count {
                    acl.take(12)?;
                    acl.bytes()?;
                }
                acl.end()?;
            }
            if flags & 0x200 != 0 {
                self.u32()?;
                if version >= 6 {
                    self.u32()?;
                }
            }
            if version >= 6 {
                if flags & 0x800 != 0 {
                    self.take(1)?;
                }
                if flags & 0x1000 != 0 {
                    self.bytes()?;
                }
                if flags & 0x2000 != 0 {
                    self.u32()?;
                }
                if flags & 0x4000 != 0 {
                    self.bytes()?;
                }
            }
        }
        if flags & 0x8000_0000 != 0 {
            let count = self.u32()? as usize;
            if count > self.0.len() / 8 {
                return Err(Error::Malformed);
            }
            for _ in 0..count {
                self.bytes()?;
                self.bytes()?;
            }
        }
        Ok(FileAttributes {
            kind,
            size,
            permissions,
            mtime,
        })
    }
    fn time(&mut self, flags: u32) -> Result<i64> {
        let seconds = self.u64()? as i64;
        let nanos = if flags & 0x100 != 0 { self.u32()? } else { 0 };
        let millis = i128::from(seconds) * 1000 + i128::from(nanos / 1_000_000);
        Ok(millis.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
    }
    fn end_indicator(&mut self, version: u32) -> Result<bool> {
        let end = version >= 6 && !self.0.is_empty() && self.take(1)?[0] != 0;
        self.end()?;
        Ok(end)
    }
    fn strings(&mut self) -> Result<bool> {
        let count = self.u32()? as usize;
        if count > self.0.len() / 4 {
            return Err(Error::Malformed);
        }
        let mut copy = false;
        for _ in 0..count {
            copy |= self.bytes()? == b"copy-file";
        }
        Ok(copy)
    }
}
fn string(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let n = u32::try_from(value.len()).map_err(|_| Error::Malformed)?;
    output.extend(n.to_be_bytes());
    output.extend(value);
    Ok(())
}
fn supported(value: &[u8], second: bool) -> Result<bool> {
    let mut r = Reader(value);
    r.take(if second { 24 } else { 20 })?;
    let copy = if second {
        r.strings()?;
        r.strings()?
    } else {
        let mut copy = false;
        while !r.0.is_empty() {
            copy |= r.bytes()? == b"copy-file";
        }
        copy
    };
    r.end()?;
    Ok(copy)
}
fn version(value: &[u8]) -> Result<(u32, bool)> {
    let mut r = Reader(value);
    if r.take(1)? != [2] {
        return Err(Error::Malformed);
    }
    let version = r.u32()?;
    if !(3..=6).contains(&version) {
        return Err(Error::Malformed);
    }

    let mut extensions = HashMap::new();
    while !r.0.is_empty() {
        let name = r.text()?;
        let value = r.bytes()?.to_vec();
        extensions.insert(name, value);
    }
    let mut copy = extensions.contains_key("copy-file");
    for (name, second) in [("supported", false), ("supported2", true)] {
        if let Some(bytes) = extensions.get(name) {
            copy |= supported(bytes, second)?;
        }
    }
    Ok((version, copy))
}
async fn frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let len = stream.read_u32().await.map_err(|_| Error::Malformed)? as usize;
    if !(1..=MAX_PACKET).contains(&len) {
        return Err(Error::Malformed);
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::Malformed)?;
    Ok(bytes)
}
fn response(bytes: &[u8], id: u32, kind: u8) -> Result<Reader<'_>> {
    let mut reader = Reader(bytes);
    let tag = reader.take(1)?[0];
    if reader.u32()? != id {
        return Err(Error::Malformed);
    }
    if tag == 101 {
        let code = StatusCode::from(reader.u32()?);
        reader.bytes()?;
        reader.bytes()?;
        reader.end()?;
        if code != StatusCode::Ok {
            return Err(Error::Status(Status { status_code: code }));
        }
        if kind != 101 {
            return Err(Error::Malformed);
        }
        return Ok(Reader(&[]));
    }
    if tag != kind {
        return Err(Error::Malformed);
    }
    Ok(reader)
}
struct Inner {
    stream: Stream,
    next: u32,
}
pub struct RawSftpSession {
    version: u32,
    inner: Mutex<Inner>,
    pub supports_copy: bool,
}
impl RawSftpSession {
    pub async fn new(mut stream: Stream) -> Result<Self> {
        stream
            .write_all(&[0, 0, 0, 5, 1, 0, 0, 0, 6])
            .await
            .map_err(|_| Error::Malformed)?;
        let (version, supports_copy) = version(&frame(&mut stream).await?)?;
        Ok(Self {
            version,
            inner: Mutex::new(Inner { stream, next: 1 }),
            supports_copy,
        })
    }
    async fn request(&self, kind: u8, body: Vec<u8>, expected: u8) -> Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(300), async {
            let mut inner = self.inner.lock().await;
            let id = inner.next;
            inner.next = inner.next.wrapping_add(1);
            let length = body
                .len()
                .checked_add(5)
                .filter(|n| *n <= MAX_PACKET)
                .ok_or(Error::Malformed)?;
            let mut packet = Vec::with_capacity(length + 4);
            packet.extend((length as u32).to_be_bytes());
            packet.push(kind);
            packet.extend(id.to_be_bytes());
            packet.extend(body);
            inner
                .stream
                .write_all(&packet)
                .await
                .map_err(|_| Error::Malformed)?;
            let bytes = frame(&mut inner.stream).await?;
            let reader = response(&bytes, id, expected)?;
            Ok(reader.0.to_vec())
        })
        .await
        .map_err(|_| Error::Malformed)?
    }
    async fn status(&self, kind: u8, body: Vec<u8>) -> Result<Status> {
        let bytes = self.request(kind, body, 101).await?;
        if !bytes.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Status {
            status_code: StatusCode::Ok,
        })
    }
    async fn path(&self, kind: u8, path: &str, expected: u8) -> Result<Vec<u8>> {
        let mut bytes = vec![];
        string(&mut bytes, path.as_bytes())?;
        self.request(kind, bytes, expected).await
    }
    fn names(bytes: &[u8], version: u32) -> Result<Name> {
        let mut reader = Reader(bytes);
        let count = reader.u32()? as usize;
        if count > reader.0.len() / if version == 3 { 12 } else { 9 } {
            return Err(Error::Malformed);
        }
        let mut files = vec![];
        for _ in 0..count {
            let filename = reader.text()?;
            if version == 3 {
                reader.bytes()?;
            }
            let attrs = reader.attrs(version)?;
            files.push(File { filename, attrs });
        }
        let end = reader.end_indicator(version)?;
        Ok(Name { files, end })
    }
    pub async fn realpath(&self, path: impl AsRef<str>) -> Result<Name> {
        Self::names(&self.path(16, path.as_ref(), 104).await?, self.version)
    }
    pub async fn lstat(&self, path: impl AsRef<str>) -> Result<Attrs> {
        let mut body = vec![];
        string(&mut body, path.as_ref().as_bytes())?;
        if self.version >= 4 {
            body.extend(0x8000_fffdu32.to_be_bytes());
        }
        let bytes = self.request(7, body, 105).await?;
        let mut r = Reader(&bytes);
        let attrs = r.attrs(self.version)?;
        r.end()?;
        Ok(Attrs { attrs })
    }
    pub async fn opendir(&self, path: impl AsRef<str>) -> Result<Handle> {
        let bytes = self.path(11, path.as_ref(), 102).await?;
        let mut r = Reader(&bytes);
        let handle = r.bytes()?.to_vec();
        r.end()?;
        Ok(Handle { handle })
    }
    pub async fn readdir(&self, handle: impl AsRef<[u8]>) -> Result<Name> {
        let mut bytes = vec![];
        string(&mut bytes, handle.as_ref())?;
        Self::names(&self.request(12, bytes, 104).await?, self.version)
    }
    pub async fn open(&self, path: impl AsRef<str>, flags: OpenFlags) -> Result<Handle> {
        let mut bytes = vec![];
        string(&mut bytes, path.as_ref().as_bytes())?;
        if self.version >= 5 {
            let mut access = 0u32;
            if flags.0 & 1 != 0 {
                access |= 0x81;
            }
            if flags.0 & 2 != 0 {
                access |= 0x102;
            }
            bytes.extend(access.to_be_bytes());
            let disposition = match (flags.0 & 8 != 0, flags.0 & 16 != 0) {
                (true, true) => 1u32,
                (true, false) => 3,
                (false, true) => 4,
                (false, false) => 2,
            };
            bytes.extend(disposition.to_be_bytes());
        } else {
            bytes.extend(flags.0.to_be_bytes());
        }
        self.empty_attrs(&mut bytes);
        let bytes = self.request(3, bytes, 102).await?;
        let mut r = Reader(&bytes);
        let handle = r.bytes()?.to_vec();
        r.end()?;
        Ok(Handle { handle })
    }
    fn empty_attrs(&self, bytes: &mut Vec<u8>) {
        bytes.extend(0u32.to_be_bytes());
        if self.version >= 4 {
            bytes.push(5);
        }
    }
    pub async fn close(&self, handle: impl AsRef<[u8]>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, handle.as_ref())?;
        self.status(4, bytes).await
    }
    pub async fn read(&self, handle: impl AsRef<[u8]>, offset: u64, len: u32) -> Result<Data> {
        let mut bytes = vec![];
        string(&mut bytes, handle.as_ref())?;
        bytes.extend(offset.to_be_bytes());
        bytes.extend(len.to_be_bytes());
        let bytes = self.request(5, bytes, 103).await?;
        let mut r = Reader(&bytes);
        let data = r.bytes()?.to_vec();
        if data.len() > len as usize {
            return Err(Error::Malformed);
        }
        r.end_indicator(self.version)?;
        Ok(Data { data })
    }
    pub async fn write(
        &self,
        handle: impl AsRef<[u8]>,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, handle.as_ref())?;
        bytes.extend(offset.to_be_bytes());
        string(&mut bytes, &data)?;
        self.status(6, bytes).await
    }
    pub async fn mkdir(&self, path: impl AsRef<str>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, path.as_ref().as_bytes())?;
        self.empty_attrs(&mut bytes);
        self.status(14, bytes).await
    }
    pub async fn rmdir(&self, path: impl AsRef<str>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, path.as_ref().as_bytes())?;
        self.status(15, bytes).await
    }
    pub async fn remove(&self, path: impl AsRef<str>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, path.as_ref().as_bytes())?;
        self.status(13, bytes).await
    }
    pub async fn rename(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, from.as_ref().as_bytes())?;
        string(&mut bytes, to.as_ref().as_bytes())?;
        if self.version >= 5 {
            bytes.extend(0u32.to_be_bytes());
        }
        self.status(18, bytes).await
    }
    pub async fn extended(&self, name: &str, data: Vec<u8>) -> Result<Status> {
        let mut bytes = vec![];
        string(&mut bytes, name.as_bytes())?;
        bytes.extend(data);
        self.status(200, bytes).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_handles_and_binary_extension_values_keep_all_bytes() {
        let opaque = [0, 255, 128];
        let mut bytes = vec![];
        string(&mut bytes, &opaque).unwrap();
        assert_eq!(bytes, vec![0, 0, 0, 3, 0, 255, 128]);
        assert_eq!(Reader(&bytes).bytes().unwrap(), opaque);
        let mut support = vec![255; 20];
        string(&mut support, b"copy-file").unwrap();
        let mut version = vec![2, 0, 0, 0, 3];
        string(&mut version, b"supported").unwrap();
        string(&mut version, &support).unwrap();
        assert!(super::version(&version).unwrap().1);
        support.resize(24, 0);
        support.truncate(24);
        support.extend(0u32.to_be_bytes());
        support.extend(1u32.to_be_bytes());
        string(&mut support, b"copy-file").unwrap();
        let mut version = vec![2, 0, 0, 0, 3];
        string(&mut version, b"supported2").unwrap();
        string(&mut version, &support).unwrap();
        assert!(super::version(&version).unwrap().1);
        assert!(super::version(&version[..version.len() - 1]).is_err());
        assert!(supported(&[0; 24], true).is_err());
    }
    #[test]
    fn attributes_and_response_ids_are_strict() {
        let mut attrs = vec![];
        attrs.extend(0x8000_000fu32.to_be_bytes());
        attrs.extend(512u64.to_be_bytes());
        attrs.extend([0; 8]);
        attrs.extend(0o100644u32.to_be_bytes());
        attrs.extend(0u32.to_be_bytes());
        attrs.extend(1_700_000_000u32.to_be_bytes());
        attrs.extend(1u32.to_be_bytes());
        string(&mut attrs, b"opaque").unwrap();
        string(&mut attrs, &[255, 0]).unwrap();
        let decoded = Reader(&attrs).attrs(3).unwrap();
        assert_eq!(decoded.size, Some(512));
        assert_eq!(decoded.mtime, Some(1_700_000_000_000));
        assert!(matches!(decoded.file_type(), FileType::File));
        assert!(Reader(&attrs[..attrs.len() - 1]).attrs(3).is_err());
        assert!(response(&[102, 0, 0, 0, 2], 1, 102).is_err());
    }
    #[tokio::test]
    async fn oversized_packet_is_rejected_before_reading_body() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_all(&((MAX_PACKET + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), frame(&mut reader))
                .await
                .unwrap()
                .is_err()
        );
    }
    #[test]
    fn versioned_attributes_cover_64bit_times_acl_bits_and_extensions() {
        for version in 4..=6 {
            let flags = if version == 6 {
                0x8000_fffdu32
            } else {
                0x8000_03fd
            };
            let mut bytes = flags.to_be_bytes().to_vec();
            bytes.push(1);
            bytes.extend(12u64.to_be_bytes());
            if version == 6 {
                bytes.extend(16u64.to_be_bytes());
            }
            string(&mut bytes, b"owner").unwrap();
            string(&mut bytes, b"group").unwrap();
            bytes.extend(0o644u32.to_be_bytes());
            for seconds in [1_700_000_000u64, 1_700_000_001, 4_294_967_297] {
                bytes.extend(seconds.to_be_bytes());
                bytes.extend(123_456_789u32.to_be_bytes());
            }
            if version == 6 {
                bytes.extend(1_700_000_002u64.to_be_bytes());
                bytes.extend(0u32.to_be_bytes());
            }
            let mut acl = vec![];
            if version == 6 {
                acl.extend(0u32.to_be_bytes());
            }
            acl.extend(0u32.to_be_bytes());
            string(&mut bytes, &acl).unwrap();
            bytes.extend(0u32.to_be_bytes());
            if version == 6 {
                bytes.extend(0xffff_ffffu32.to_be_bytes());
                bytes.push(2);
                string(&mut bytes, b"application/octet-stream").unwrap();
                bytes.extend(1u32.to_be_bytes());
                string(&mut bytes, &[0, 255]).unwrap();
            }
            bytes.extend(1u32.to_be_bytes());
            string(&mut bytes, b"opaque").unwrap();
            string(&mut bytes, &[0, 255]).unwrap();
            let mut reader = Reader(&bytes);
            let attrs = reader.attrs(version).unwrap();
            reader.end().unwrap();
            assert_eq!(attrs.size, Some(12));
            assert_eq!(attrs.mtime, Some(4_294_967_297_123));
            assert!(matches!(attrs.file_type(), FileType::File));
            assert!(attrs.type_known());
            for end in 0..bytes.len() {
                assert!(
                    Reader(&bytes[..end]).attrs(version).is_err(),
                    "version={version}, end={end}"
                );
            }
        }
    }
    #[test]
    fn mandatory_type_version_range_and_end_indicators_do_not_guess() {
        let mut bytes = 4u32.to_be_bytes().to_vec();
        bytes.push(5);
        bytes.extend(0o100644u32.to_be_bytes());
        let attrs = Reader(&bytes).attrs(4).unwrap();
        assert!(matches!(attrs.file_type(), FileType::Other));
        assert!(!attrs.type_known());
        let attrs = Reader(&[0, 0, 0, 0, 3]).attrs(4).unwrap();
        assert!(attrs.file_type().is_symlink() && attrs.type_known());
        assert!(Reader(&[0, 0, 0, 2, 1]).attrs(4).is_err());
        let end = RawSftpSession::names(&[0, 0, 0, 0, 1], 6).unwrap();
        assert!(end.end && end.files.is_empty());
        assert!(RawSftpSession::names(&[0, 0, 0, 0, 1], 5).is_err());
        assert!(RawSftpSession::names(&[0, 0, 0, 0, 1, 0], 6).is_err());
        for value in 0u32..=8 {
            let mut bytes = vec![2];
            bytes.extend(value.to_be_bytes());
            assert_eq!(version(&bytes).is_ok(), (3..=6).contains(&value));
        }
    }
}
