use crate::{
    management::{
        reply::{Reply, ResourceUnavailable},
        session::Session,
        wire::BODY_LIMIT,
    },
    network::{
        outbound_http::HeaderPair,
        peer::devices::{ALPN, own_channel},
        tls::Identity,
    },
    storage::files::FilePolicy,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, BodyDataStream, Bytes},
    extract::Request,
    response::{IntoResponse, Response},
    routing::any,
};
use futures_util::{StreamExt, stream};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Seek, SeekFrom},
    path::Path,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    sync::{Mutex, Semaphore, mpsc, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    callback_id: String,
    kind: String,
    port: u16,
    #[serde(default = "yes")]
    lan_access: bool,
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRange {
    path: String,
    offset: i64,
    length: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outgoing {
    status: u16,
    headers: Vec<HeaderPair>,
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    content_length: Option<i64>,
    #[serde(default)]
    host_file_range: Option<FileRange>,
}
struct ReadState {
    body: BodyDataStream,
    pending: Bytes,
    received: u64,
    limit: u64,
}
struct WriteState {
    output: Option<mpsc::Sender<std::io::Result<Vec<u8>>>>,
    written: u64,
    expected: Option<u64>,
}
struct Incoming {
    metadata: Value,
    input: Mutex<ReadState>,
    output: Mutex<WriteState>,
    ready: watch::Sender<bool>,
    cancel: CancellationToken,
    all_queued: AtomicBool,
    finished: AtomicBool,
    network_done: AtomicBool,
}
struct Release {
    session: Weak<Session>,
    id: String,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pending: Option<Arc<Incoming>>,
}
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(pending) = &self.pending {
            pending.network_done.store(true, Ordering::SeqCst);
            if pending.all_queued.load(Ordering::SeqCst) && !pending.finished.load(Ordering::SeqCst)
            {
                return;
            }
        }
        if let Some(session) = self.session.upgrade() {
            session.release(&self.id);
        }
    }
}
#[derive(Clone)]
struct Relay {
    session: Weak<Session>,
    callback: String,
    files: Arc<FilePolicy>,
    port: u16,
    limit: u64,
    kind: String,
    control: Arc<Semaphore>,
    data: Arc<Semaphore>,
}
fn loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map(|v| v.is_loopback())
            .unwrap_or(v.is_loopback()),
        std::net::IpAddr::V4(v) => v.is_loopback(),
    }
}

pub fn bind_public(port: u16) -> std::io::Result<TcpListener> {
    let dual = || -> std::io::Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(false)?;
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&std::net::SocketAddr::from(([0u16; 8], port)).into())?;
        socket.listen(128)?;
        TcpListener::from_std(socket.into())
    };
    dual().or_else(|_| {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&std::net::SocketAddr::from(([0u8; 4], port)).into())?;
        socket.listen(128)?;
        TcpListener::from_std(socket.into())
    })
}
fn approval_port(port: u16) -> u16 {
    if port <= 65533 { port + 2 } else { port - 2 }
}
async fn relay(
    state: Relay,
    request: Request,
    scheme: &'static str,
    peer: std::net::SocketAddr,
) -> Response {
    match relay_inner(state, request, scheme, peer).await {
        Ok(response) => response,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            Reply::from_error(error).into_response()
        }
        Err(_) => Reply::error(500, "platform_error", "platform operation failed").into_response(),
    }
}
async fn relay_inner(
    state: Relay,
    request: Request,
    scheme: &'static str,
    peer: std::net::SocketAddr,
) -> Result<Response> {
    let session = state.session.upgrade().context("session closed")?;
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let device = state.kind == "device";
    let streaming = if device {
        matches!(path, "/api/files/write-bytes" | "/api/files/stream-upload")
    } else {
        matches!(path, "/api/share/upload" | "/api/web-ui/files")
    };
    let limit = if streaming && state.limit >= 8 * 1024 * 1024 {
        128 * 1024 * 1024
    } else {
        state.limit
    };
    let permit = if device {
        let slots = if matches!(
            path,
            "/api/files/read-bytes" | "/api/files/stream-file" | "/api/files/stream-upload"
        ) {
            &state.data
        } else {
            &state.control
        };
        match slots.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return Ok(Reply::error(503, "busy", "request capacity reached").into_response());
            }
        }
    } else {
        None
    };
    let content_length = parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .map(str::parse::<u64>)
        .transpose()?
        .or_else(|| {
            if parts.headers.contains_key("transfer-encoding") {
                None
            } else {
                Some(0)
            }
        });
    let chunked = parts.headers.contains_key("transfer-encoding");
    let too_large = || {
        let mut reply = Reply::json(json!({"error":"request body exceeds limit"}));
        reply.status = 413;
        reply.headers.insert("connection".into(), "close".into());
        reply.into_response()
    };
    if content_length.is_some_and(|size| size > limit)
        || !device && streaming && chunked
        || !device
            && !streaming
            && matches!(parts.method.as_str(), "GET" | "HEAD" | "OPTIONS")
            && (chunked || content_length != Some(0))
    {
        return Ok(too_large());
    }
    let body = if !streaming {
        match axum::body::to_bytes(body, limit as usize).await {
            Ok(bytes) => Body::from(bytes),
            Err(_) => return Ok(too_large()),
        }
    } else {
        body
    };
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &parts.headers {
        headers
            .entry(name.to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| url::Url::parse(&format!("{scheme}://{h}")).ok())
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "127.0.0.1".into());
    let metadata = json!({"method":parts.method.as_str(),"uri":parts.uri.to_string(),"headers":headers,"remoteHost":peer.ip().to_string(),"scheme":scheme,"host":host,"port":state.port,"contentLength":content_length});
    let (output, receiver) = mpsc::channel(1);
    let (ready, _) = watch::channel(false);
    let cancel = CancellationToken::new();
    let close = cancel.clone();
    let id = session.own_with_close(
        Incoming {
            metadata,
            input: Mutex::new(ReadState {
                body: body.into_data_stream(),
                pending: Bytes::new(),
                received: 0,
                limit,
            }),
            output: Mutex::new(WriteState {
                output: Some(output),
                written: 0,
                expected: None,
            }),
            ready,
            cancel,
            all_queued: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            network_done: AtomicBool::new(false),
        },
        move || close.cancel(),
    )?;
    let mut release = Release {
        session: Arc::downgrade(&session),
        id: id.clone(),
        _permit: permit,
        pending: None,
    };
    let reply = session
        .callback(&state.callback, "http-request", id.as_bytes().to_vec())
        .await?;
    let response: Outgoing = serde_json::from_slice(&reply)?;
    ensure!(
        (100..=599).contains(&response.status) && response.content_length.is_none_or(|n| n >= 0),
        "invalid HTTP response metadata"
    );
    let mut builder = axum::http::Response::builder().status(response.status);
    for header in response.headers {
        ensure!(
            !header.second.contains(['\r', '\n', '\0']),
            "invalid HTTP response header"
        );
        let name = axum::http::HeaderName::from_bytes(header.first.as_bytes())?;
        let value = axum::http::HeaderValue::from_str(&header.second)?;
        if !matches!(name.as_str(), "content-length" | "transfer-encoding") {
            builder = builder.header(name, value);
        }
    }
    let expected = response.content_length.map(|n| n as u64);
    if let Some(expected) = expected {
        builder = builder.header("content-length", expected);
    }
    if let Some(range) = response.host_file_range {
        ensure!(
            range.offset >= 0
                && range.length >= 0
                && range.offset.checked_add(range.length).is_some()
                && response.content_length == Some(range.length),
            "invalid host file response range"
        );
        let mut file = state
            .files
            .open(Path::new(&range.path), &session, false, false, false)?
            .into_std();
        let size = file.metadata()?.len();
        ensure!(
            range.offset as u64 <= size && range.length as u64 <= size - range.offset as u64,
            "invalid host file range"
        );
        file.seek(SeekFrom::Start(range.offset as u64))?;
        let file = tokio::fs::File::from_std(file).take(range.length as u64);
        let source = ReaderStream::new(file);
        let source = stream::unfold(
            (source, Some(release)),
            |(mut source, release)| async move {
                source.next().await.map(|bytes| (bytes, (source, release)))
            },
        );
        return Ok(builder.body(Body::from_stream(source))?);
    }
    let pending = session.resource::<Incoming>(&id)?;
    pending.output.lock().await.expected = expected;
    pending
        .all_queued
        .store(expected == Some(0), Ordering::SeqCst);
    release.pending = Some(pending.clone());
    pending.ready.send_replace(true);
    let source = stream::unfold(
        (receiver, 0u64, false, Some(release)),
        move |(mut receiver, received, finished, release)| async move {
            if finished {
                return None;
            }
            match receiver.recv().await {
                Some(Ok(bytes)) => {
                    let size = bytes.len() as u64;
                    Some((Ok(bytes), (receiver, received + size, false, release)))
                }
                Some(Err(error)) => Some((Err(error), (receiver, received, true, release))),
                None if expected.is_some_and(|n| n != received) => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "incomplete platform response",
                    )),
                    (receiver, received, true, release),
                )),
                None => None,
            }
        },
    );
    Ok(builder.body(Body::from_stream(source))?)
}
async fn http_connection(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    state: Relay,
    scheme: &'static str,
    peer: std::net::SocketAddr,
) {
    let router = Router::new().fallback(any(move |request: Request| {
        relay(state.clone(), request, scheme, peer)
    }));
    let service = TowerToHyperService::new(router);
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(300))
        .max_headers(96)
        .max_buf_size(64 * 1024)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}
pub async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
    identity: &Identity,
    files: Arc<FilePolicy>,
) -> Result<Reply> {
    ensure!(body.len() <= BODY_LIMIT, "listener message too large");
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let operation = path
        .strip_prefix("/api/web-ui/platform/listeners")
        .context("invalid listener route")?;
    if method == "POST" && operation.is_empty() {
        let input: Open = serde_json::from_slice(&body)?;
        ensure!(
            input.port != 0
                && !input.callback_id.is_empty()
                && input.callback_id.len() <= 128
                && matches!(input.kind.as_str(), "link-share" | "mcp" | "device"),
            "invalid listener configuration"
        );
        use crate::access::Feature;
        session.access.require(match input.kind.as_str() {
            "device" => Feature::Devices,
            "mcp" => Feature::Mcp,
            _ => Feature::Shares,
        })?;
        let mut listeners = if input.kind != "mcp" || input.lan_access {
            vec![bind_public(input.port)?]
        } else {
            let v4 = TcpListener::bind(("127.0.0.1", input.port)).await?;
            let mut listeners = vec![v4];
            if let Ok(v6) = TcpListener::bind(("::1", input.port)).await {
                listeners.push(v6);
            }
            listeners
        };
        let approval = if input.kind == "device" {
            Some(bind_public(approval_port(input.port))?)
        } else {
            None
        };
        let mut tls = (*identity.server).clone();
        if input.kind == "device" {
            tls.alpn_protocols = vec![ALPN.to_vec()];
        }
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let approval_acceptor = tokio_rustls::TlsAcceptor::from(identity.server.clone());
        let state = Relay {
            session: Arc::downgrade(session),
            callback: input.callback_id.clone(),
            files,
            port: input.port,
            limit: if input.kind == "mcp" {
                1024 * 1024
            } else {
                8 * 1024 * 1024
            },
            kind: input.kind.clone(),
            control: Arc::new(Semaphore::new(32)),
            data: Arc::new(Semaphore::new(64)),
        };
        let stop = CancellationToken::new();
        let close = stop.clone();
        let session_stop = session.cancel.clone();
        let owner = Arc::downgrade(session);
        let (start, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let connections = Arc::new(Semaphore::new(if input.kind == "device" {
                96
            } else {
                128
            }));
            let http_slots = Arc::new(Semaphore::new(64));
            let tls_slots = Arc::new(Semaphore::new(64));
            let mut jobs = JoinSet::new();
            if let Some(listener) = approval {
                let acceptor = approval_acceptor;
                let mut state = state.clone();
                state.limit = 64 * 1024;
                state.kind = "approval".into();
                state.port = approval_port(input.port);
                let stop = stop.clone();
                let slots = Arc::new(Semaphore::new(64));
                jobs.spawn(async move {
                    let mut clients=JoinSet::new();
                    loop{tokio::select!{
                        _=stop.cancelled()=>break,
                        _=clients.join_next(),if !clients.is_empty()=>{},
                        accepted=listener.accept()=>{
                            let Ok((stream,peer))=accepted else{break};let Ok(permit)=slots.clone().try_acquire_owned()else{continue};
                            let acceptor=acceptor.clone();let state=state.clone();
                            clients.spawn(async move{let _permit=permit;if let Ok(Ok(stream))=timeout(Duration::from_secs(30),acceptor.accept(stream)).await{http_connection(stream,state,"https",peer).await;}});
                        }
                    }}
                });
            }
            for listener in listeners.drain(..) {
                let http_slots = http_slots.clone();
                let tls_slots = tls_slots.clone();
                let acceptor = acceptor.clone();
                let state = state.clone();
                let slots = connections.clone();
                let kind = input.kind.clone();
                let stop = stop.clone();
                let owner = owner.clone();
                jobs.spawn(async move {
                    let mut clients=JoinSet::new();
                    loop{tokio::select!{
                        _=stop.cancelled()=>break,
                        _=clients.join_next(),if !clients.is_empty()=>{},
                        accepted=listener.accept()=>{
                            let Ok((stream,peer))=accepted else{break};let Ok(permit)=slots.clone().try_acquire_owned()else{continue};
                            let acceptor=acceptor.clone();let state=state.clone();let kind=kind.clone();let owner=owner.clone();let http_slots=http_slots.clone();let tls_slots=tls_slots.clone();
                            clients.spawn(async move{
                                let _permit=permit;let mut first=[0u8;1];
                                if !matches!(timeout(Duration::from_secs(3),stream.peek(&mut first)).await,Ok(Ok(1))){return;}
                                if first[0]==22 {
                                    let _scheme_permit=if kind=="device"{None}else{match tls_slots.try_acquire_owned(){Ok(permit)=>Some(permit),Err(_)=>return}};
                                    let Ok(Ok(stream))=timeout(Duration::from_secs(30),acceptor.accept(stream)).await else{return};
                                    if kind=="device" {
                                        if stream.get_ref().1.alpn_protocol()!=Some(ALPN){return;}
                                        let Some(session)=owner.upgrade()else{return};
                                        if let Ok((id,channel))=own_channel(&session,stream.into()){
                                            let _release=Release{session:Arc::downgrade(&session),id:id.clone(),_permit:None,pending:None};
                                            let event=serde_json::to_vec(&json!({"handle":id,"remoteHost":peer.ip().to_string()})).unwrap();
                                            if session.emit(&state.callback,"device-accepted",event,false).is_ok(){channel.cancel.cancelled().await;}
                                        }
                                    }else{http_connection(stream,state,"https",peer).await;}
                                }else if kind=="link-share"||loopback(peer.ip()){
                                    let _scheme_permit=if kind=="device"{None}else{match http_slots.try_acquire_owned(){Ok(permit)=>Some(permit),Err(_)=>return}};
                                    http_connection(stream,state,"http",peer).await;
                                }
                            });
                        }
                    }}
                });
            }
            tokio::select! {_=stop.cancelled()=>{},_=session_stop.cancelled()=>{}}
        });
        let abort = task.abort_handle();
        let id = session.own_with_wait(close.clone(), move || close.cancel(), task);
        match id {
            Ok(id) => {
                let _ = start.send(());
                Ok(Reply::json(
                    json!({"handle":id,"httpsPort":input.port,"fingerprint":identity.fingerprint}),
                ))
            }
            Err(error) => {
                while !abort.is_finished() {
                    tokio::task::yield_now().await;
                }
                Err(error)
            }
        }
    } else {
        let query = crate::management::wire::query(query);
        let pending =
            session.resource::<Incoming>(query.get("handle").context("handle required")?)?;
        match (method, operation) {
            ("GET", "/requests") => Ok(Reply::json(pending.metadata.clone())),
            ("GET", "/body") => {
                let length = query
                    .get("length")
                    .map(|n| n.parse::<usize>())
                    .transpose()?
                    .unwrap_or(BODY_LIMIT);
                ensure!(
                    (1..=BODY_LIMIT).contains(&length),
                    "invalid listener read length"
                );
                let mut input = pending.input.lock().await;
                while input.pending.is_empty() {
                    let next = tokio::select! {
                        biased;
                        _=pending.cancel.cancelled()=>return Err(ResourceUnavailable("HTTP request closed").into()),
                        next=input.body.next()=>next,
                    };
                    match next {
                        Some(Ok(bytes)) => {
                            input.received += bytes.len() as u64;
                            ensure!(input.received <= input.limit, "HTTP request body too large");
                            input.pending = bytes;
                        }
                        Some(Err(_)) => {
                            return Err(crate::management::reply::PlatformFailure.into());
                        }
                        None => {
                            let mut reply = Reply::bytes(vec![]);
                            reply
                                .headers
                                .insert("x-folderspan-end".into(), "true".into());
                            return Ok(reply);
                        }
                    }
                }
                let size = length.min(input.pending.len());
                let mut reply = Reply::bytes(input.pending.split_to(size).to_vec());
                reply
                    .headers
                    .insert("x-folderspan-end".into(), "false".into());
                Ok(reply)
            }
            ("PUT", "/body") => {
                let mut ready = pending.ready.subscribe();
                while !*ready.borrow() {
                    tokio::select! {_=pending.cancel.cancelled()=>return Err(ResourceUnavailable("HTTP request closed").into()),changed=ready.changed()=>changed?,}
                }
                let mut output = pending.output.lock().await;
                ensure!(
                    output.expected.is_none_or(
                        |n| output.written <= n && body.len() as u64 <= n - output.written
                    ),
                    "HTTP response length exceeded"
                );
                let length = body.len();
                if output.expected == Some(output.written + length as u64) {
                    pending.all_queued.store(true, Ordering::SeqCst);
                }
                let sender = output.output.as_ref().context("HTTP response finished")?;
                tokio::select! {_=pending.cancel.cancelled()=>return Err(ResourceUnavailable("HTTP request closed").into()),result=sender.send(Ok(body))=>result.map_err(|_|ResourceUnavailable("HTTP response closed"))?,}
                output.written += length as u64;
                Ok(Reply::json(true))
            }
            ("POST", "/body") => {
                pending.finished.store(true, Ordering::SeqCst);
                let mut output = pending.output.lock().await;
                if query.get("failed").is_some_and(|v| v == "true") {
                    if let Some(sender) = output.output.take() {
                        let _ = sender
                            .send(Err(std::io::Error::other("browser response failed")))
                            .await;
                    }
                } else {
                    output.output.take();
                }
                drop(output);
                if pending.network_done.load(Ordering::SeqCst) {
                    session.release(query.get("handle").unwrap());
                }
                Ok(Reply::json(true))
            }
            _ => Ok(Reply::error(404, "not_found", "unknown listener operation")),
        }
    }
}
