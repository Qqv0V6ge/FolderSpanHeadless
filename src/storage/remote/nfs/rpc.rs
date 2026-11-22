use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::nfs::xdr::{Reader, Writer},
};
use anyhow::{Result, ensure};
use std::{
    net::{Shutdown, TcpStream as StdTcp},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

const MAX_RECORD: usize = 8 * 1024 * 1024;
pub(crate) struct Auth {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}
pub(crate) struct Rpc {
    stream: Mutex<TcpStream>,
    socket: StdTcp,
    auth: Auth,
}
impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
struct Inflight<'a> {
    socket: &'a StdTcp,
    complete: bool,
}
impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }
}
pub(crate) async fn record(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    for _ in 0..128 {
        let marker = stream.read_u32().await.map_err(|_| PlatformFailure)?;
        let length = (marker & 0x7fff_ffff) as usize;
        ensure!(
            length <= MAX_RECORD - bytes.len(),
            "RPC record exceeds its limit"
        );
        let start = bytes.len();
        bytes.resize(start + length, 0);
        stream
            .read_exact(&mut bytes[start..])
            .await
            .map_err(|_| PlatformFailure)?;
        if marker & 0x8000_0000 != 0 {
            return Ok(bytes);
        }
    }
    Err(ResourceUnavailable("too many RPC fragments").into())
}
impl Rpc {
    pub async fn connect(host: &str, port: u16, auth: Auth) -> Result<Self> {
        ensure!(
            port > 0 && auth.groups.len() <= 16,
            "invalid NFS identity or port"
        );
        let stream =
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
                .await
                .map_err(|_| PlatformFailure)?
                .map_err(|_| PlatformFailure)?;
        stream.set_nodelay(true).map_err(|_| PlatformFailure)?;
        let stream = stream.into_std().map_err(|_| PlatformFailure)?;
        let socket = stream.try_clone().map_err(|_| PlatformFailure)?;
        let stream = TcpStream::from_std(stream).map_err(|_| PlatformFailure)?;
        Ok(Self {
            stream: Mutex::new(stream),
            socket,
            auth,
        })
    }
    pub async fn call(
        &self,
        program: u32,
        version: u32,
        procedure: u32,
        args: Writer,
    ) -> Result<Reader> {
        let mut credentials = Writer::default();
        credentials.u32(0);
        credentials.string("FolderSpan");
        credentials.u32(self.auth.uid);
        credentials.u32(self.auth.gid);
        credentials.u32(self.auth.groups.len() as u32);
        for group in &self.auth.groups {
            credentials.u32(*group);
        }
        let xid = rand::random::<u32>();
        let mut packet = Writer::default();
        for value in [xid, 0, 2, program, version, procedure, 1] {
            packet.u32(value);
        }
        packet.opaque(&credentials.0);
        packet.u32(0);
        packet.u32(0);
        packet.fixed(&args.0);
        ensure!(packet.0.len() <= MAX_RECORD, "RPC call exceeds its limit");
        let mut stream = self.stream.lock().await;
        let mut guard = Inflight {
            socket: &self.socket,
            complete: false,
        };
        let response = tokio::time::timeout(Duration::from_secs(30), async {
            stream
                .write_u32(packet.0.len() as u32 | 0x8000_0000)
                .await
                .map_err(|_| PlatformFailure)?;
            stream
                .write_all(&packet.0)
                .await
                .map_err(|_| PlatformFailure)?;
            stream.flush().await.map_err(|_| PlatformFailure)?;
            record(&mut *stream).await
        })
        .await
        .map_err(|_| ResourceUnavailable("NFS RPC timed out"))??;
        let mut reader = Reader::new(response);
        ensure!(
            reader.u32()? == xid && reader.u32()? == 1,
            ResourceUnavailable("unexpected RPC response")
        );
        ensure!(
            reader.u32()? == 0,
            ResourceUnavailable("RPC authentication or protocol rejected")
        );
        reader.u32()?;
        reader.opaque(1024)?;
        ensure!(
            reader.u32()? == 0,
            ResourceUnavailable("RPC procedure unavailable")
        );
        guard.complete = true;
        Ok(reader)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rpc_fragment_vector_limits_and_cancel_do_not_resynchronize_or_replay() {
        let mut bytes = vec![];
        bytes.extend(2u32.to_be_bytes());
        bytes.extend([1, 2]);
        bytes.extend(0x8000_0001u32.to_be_bytes());
        bytes.push(3);
        assert_eq!(record(&mut bytes.as_slice()).await.unwrap(), [1, 2, 3]);
        let oversize = (0x8000_0000u32 | ((MAX_RECORD + 1) as u32)).to_be_bytes();
        assert!(record(&mut oversize.as_slice()).await.is_err());
        assert!(record(&mut vec![0; 128 * 4].as_slice()).await.is_err());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sent, received) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = record(&mut stream).await.unwrap();
            let mut r = Reader::new(request);
            let xid = r.u32().unwrap();
            assert_eq!(r.u32().unwrap(), 0);
            assert_eq!(r.u32().unwrap(), 2);
            assert_eq!(
                (r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap()),
                (100003, 4, 1)
            );
            assert_eq!(r.u32().unwrap(), 1);
            let mut auth = Reader::new(r.opaque(1024).unwrap());
            assert_eq!(auth.u32().unwrap(), 0);
            assert_eq!(auth.string(64).unwrap(), "FolderSpan");
            assert_eq!(
                (
                    auth.u32().unwrap(),
                    auth.u32().unwrap(),
                    auth.u32().unwrap()
                ),
                (123, 456, 1)
            );
            assert_eq!(auth.u32().unwrap(), 789);
            auth.end().unwrap();
            assert_eq!((r.u32().unwrap(), r.u32().unwrap()), (0, 0));
            r.end().unwrap();
            let mut response = Writer::default();
            for value in [xid, 1, 0, 0, 0, 0] {
                response.u32(value);
            }
            stream
                .write_u32(0x8000_0000 | response.0.len() as u32)
                .await
                .unwrap();
            stream.write_all(&response.0).await.unwrap();
            record(&mut stream).await.unwrap();
            sent.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let rpc = Rpc::connect(
            "127.0.0.1",
            port,
            Auth {
                uid: 123,
                gid: 456,
                groups: vec![789],
            },
        )
        .await
        .unwrap();
        rpc.call(100003, 4, 1, Writer::default())
            .await
            .unwrap()
            .end()
            .unwrap();
        {
            let pending = rpc.call(100003, 4, 1, Writer::default());
            tokio::pin!(pending);
            tokio::select! {_=received=>{},result=&mut pending=>panic!("RPC ended before cancellation: {}",result.is_ok())}
        }
        assert!(rpc.call(100003, 4, 1, Writer::default()).await.is_err());
        drop(rpc);
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
