use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
        wire::BODY_LIMIT,
    },
    network::{tls::Identity, tls_client::fingerprint_config},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const ALPN: &[u8] = b"folderspan/1";
pub struct Channel {
    pub(crate) read: Arc<Mutex<ReadHalf<tokio_rustls::TlsStream<TcpStream>>>>,
    pub(crate) write: Arc<Mutex<WriteHalf<tokio_rustls::TlsStream<TcpStream>>>>,
    pub cancel: CancellationToken,
    pub(crate) transport: std::sync::Mutex<Option<Arc<crate::network::peer::transport::Transport>>>,
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
pub fn own_channel(
    session: &Arc<Session>,
    stream: tokio_rustls::TlsStream<TcpStream>,
) -> Result<(String, Arc<Channel>)> {
    let socket = socket2::SockRef::from(stream.get_ref().0).try_clone()?;
    let (read, write) = tokio::io::split(stream);
    let cancel = CancellationToken::new();
    let close = cancel.clone();
    let id = session.own_with_close(
        Channel {
            read: Arc::new(Mutex::new(read)),
            write: Arc::new(Mutex::new(write)),
            transport: std::sync::Mutex::new(None),
            cancel,
        },
        move || {
            close.cancel();
            let _ = socket.shutdown(std::net::Shutdown::Both);
        },
    )?;
    let channel = session.resource::<Channel>(&id)?;
    Ok((id, channel))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Connect {
    host: String,
    port: u16,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    connect_timeout_millis: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UdpListen {
    callback_id: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Verify {
    public_key: String,
    payload: Vec<i8>,
    signature: String,
}
fn mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
pub fn local_peer(ip: IpAddr) -> bool {
    match mapped(ip) {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            a == 10 || a == 127 || a == 172 && (16..=31).contains(&b) || a == 192 && b == 168
        }
        IpAddr::V6(ip) => ip.segments()[0] == 0xfe80 || ip.segments()[0] & 0xfe00 == 0xfc00,
    }
}
fn udp_socket(port: u16) -> std::io::Result<UdpSocket> {
    let make = |ipv6: bool| -> std::io::Result<UdpSocket> {
        let socket = socket2::Socket::new(
            if ipv6 {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        if ipv6 {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        let address: SocketAddr = if ipv6 {
            ([0u16; 8], port).into()
        } else {
            ([0u8; 4], port).into()
        };
        socket.bind(&address.into())?;
        UdpSocket::from_std(socket.into())
    };
    make(true).or_else(|_| make(false))
}
pub async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
    identity: &Identity,
    files: Arc<crate::storage::files::FilePolicy>,
) -> Result<Reply> {
    ensure!(body.len() <= BODY_LIMIT, "device body too large");
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let operation = path
        .strip_prefix("/api/web-ui/platform/devices/")
        .context("invalid device path")?;
    let query = crate::management::wire::query(query);
    if operation == "transfers" {
        return crate::network::peer::transfer::status(method, raw, session).await;
    }
    if operation == "transport" {
        if method == "POST" && query.get("operation").is_some_and(|v| v == "transfer") {
            let channel = session
                .resource::<Channel>(query.get("handle").context("device handle required")?)?;
            return crate::network::peer::transfer::open(body, session, &channel, files).await;
        }
        return crate::network::peer::transport::handle(method, raw, body, session).await;
    }
    match (method, operation) {
        ("POST", "connect") => {
            let input: Connect = serde_json::from_slice(&body)?;
            ensure!(
                !input.host.trim().is_empty()
                    && input.port != 0
                    && input.connect_timeout_millis <= 30_000
                    && input
                        .fingerprint
                        .as_ref()
                        .is_none_or(|p| !p.trim().is_empty()),
                "invalid device endpoint"
            );
            let mut config = fingerprint_config(input.fingerprint.as_deref())?;
            config.alpn_protocols = vec![ALPN.to_vec()];
            let connect = async {
                let tcp = TcpStream::connect((input.host.as_str(), input.port)).await?;
                let name = rustls::pki_types::ServerName::try_from(input.host)?;
                let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(name, tcp)
                    .await?;
                ensure!(
                    stream.get_ref().1.alpn_protocol() == Some(ALPN),
                    "missing device ALPN"
                );
                let certificate = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .context("device certificate is missing")?;
                let fingerprint = hex::encode_upper(Sha256::digest(certificate.as_ref()));
                Ok::<_, anyhow::Error>((stream, fingerprint))
            };
            let timeout_millis = match input.connect_timeout_millis {
                0 => 30_000,
                millis => millis,
            };
            let (stream, fingerprint) = timeout(Duration::from_millis(timeout_millis), connect)
                .await
                .map_err(|_| PlatformFailure)?
                .map_err(|_| PlatformFailure)?;
            let (handle, _) = own_channel(session, stream.into())?;
            Ok(Reply::json(
                json!({"handle":handle,"fingerprint":fingerprint}),
            ))
        }
        ("GET", "channel") => {
            let channel =
                session.resource::<Channel>(query.get("handle").context("handle required")?)?;
            let length = query
                .get("length")
                .context("length required")?
                .parse::<usize>()?;
            ensure!(
                (1..=BODY_LIMIT).contains(&length),
                "invalid device read length"
            );
            ensure!(
                channel.transport.lock().unwrap().is_none(),
                "device channel uses framed transport"
            );
            let mut reader = channel.read.lock().await;
            ensure!(
                channel.transport.lock().unwrap().is_none(),
                "device channel uses framed transport"
            );
            let mut bytes = vec![0; length];
            let count = tokio::select! {
                biased;
                _=channel.cancel.cancelled()=>return Err(ResourceUnavailable("device channel closed").into()),
                result=reader.read(&mut bytes)=>result?,
            };
            bytes.truncate(count);
            let mut reply = Reply::bytes(bytes);
            reply
                .headers
                .insert("x-folderspan-end".into(), (count == 0).to_string());
            Ok(reply)
        }
        ("PUT", "channel") => {
            let channel =
                session.resource::<Channel>(query.get("handle").context("handle required")?)?;
            ensure!(
                channel.transport.lock().unwrap().is_none(),
                "device channel uses framed transport"
            );
            let mut writer = channel.write.lock().await;
            ensure!(
                channel.transport.lock().unwrap().is_none(),
                "device channel uses framed transport"
            );
            tokio::select! {
                biased;
                _=channel.cancel.cancelled()=>return Err(ResourceUnavailable("device channel closed").into()),
                result=async{writer.write_all(&body).await?;writer.flush().await}=>result?,
            };
            Ok(Reply::json(true))
        }
        ("POST", "sign") => Ok(Reply::json(identity.sign(&body))),
        ("POST", "certificate-key") => {
            Ok(Reply::json(Identity::public_key_from_certificate(&body)))
        }
        ("POST", "verify") => {
            let input: Verify = serde_json::from_slice(&body)?;
            let bytes = input
                .payload
                .into_iter()
                .map(|b| b as u8)
                .collect::<Vec<_>>();
            Ok(Reply::json(Identity::verify(
                &input.public_key,
                &bytes,
                &input.signature,
            )))
        }
        ("POST", "udp/broadcast") => {
            let port = query.get("port").context("port required")?.parse::<u16>()?;
            ensure!(port != 0 && body.len() <= 2048, "invalid UDP beacon");
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
            socket.set_broadcast(true)?;
            let mut destinations = HashSet::from([Ipv4Addr::BROADCAST]);
            for interface in if_addrs::get_if_addrs()? {
                if !interface.ip().is_loopback() {
                    if let if_addrs::IfAddr::V4(address) = interface.addr {
                        if let Some(broadcast) = address.broadcast {
                            destinations.insert(broadcast);
                        }
                    }
                }
            }
            for destination in destinations {
                let _ = socket.send_to(&body, (destination, port)).await;
            }
            Ok(Reply::json(true))
        }
        ("POST", "udp/listen") => {
            let input: UdpListen = serde_json::from_slice(&body)?;
            ensure!(
                input.port != 0 && input.callback_id.len() <= 128 && !input.callback_id.is_empty(),
                "invalid UDP listener"
            );
            let socket = udp_socket(input.port)?;
            let owner = Arc::downgrade(session);
            let stop = session.cancel.clone();
            let task = tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
                loop {
                    let received = tokio::select! {_=stop.cancelled()=>break,result=socket.recv_from(&mut buffer)=>result};
                    match received {
                        Ok((count, peer)) if local_peer(peer.ip()) => {
                            let Some(session) = owner.upgrade() else {
                                break;
                            };
                            let payload =
                                buffer[..count].iter().map(|b| *b as i8).collect::<Vec<_>>();
                            let value =
                                json!({"host":mapped(peer.ip()).to_string(),"payload":payload});
                            if session
                                .emit(
                                    &input.callback_id,
                                    "udp-packet",
                                    serde_json::to_vec(&value).unwrap(),
                                    false,
                                )
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            if let Some(session) = owner.upgrade() {
                                let _ = session.emit(
                                    &input.callback_id,
                                    "udp-error",
                                    b"UDP listener failed".to_vec(),
                                    false,
                                );
                            }
                            break;
                        }
                    }
                }
            });
            let abort = task.abort_handle();
            let close = abort.clone();
            Ok(Reply::json(
                json!({"id":session.own_with_wait(abort,move||close.abort(),task)?}),
            ))
        }
        _ => Ok(Reply::error(
            404,
            "not_found",
            "unknown device platform operation",
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_filters_match_the_upstream_local_networks() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.1.2",
            "192.168.2.3",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(local_peer(ip.parse().unwrap()));
        }
        for ip in ["8.8.8.8", "172.15.1.2", "2001:db8::1", "::1"] {
            assert!(!local_peer(ip.parse().unwrap()));
        }
    }
}
