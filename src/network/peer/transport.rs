use crate::{
    management::{
        reply::{Reply, ResourceUnavailable},
        session::Session,
        wire::BODY_LIMIT,
    },
    network::peer::devices::Channel,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
};
use tokio_util::sync::CancellationToken;

pub const PAYLOAD_LIMIT: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub stream: i32,
    pub body: Vec<u8>,
}
impl Frame {
    fn header(bytes: &[u8]) -> Result<(u8, i32, usize)> {
        ensure!(bytes.len() >= 9, "truncated device frame");
        let kind = bytes[0];
        let stream = i32::from_le_bytes(bytes[1..5].try_into()?);
        let length = i32::from_le_bytes(bytes[5..9].try_into()?);
        ensure!((1..=8).contains(&kind), "unknown device frame type");
        ensure!(stream >= 0, "negative device stream");
        ensure!(
            (0..=PAYLOAD_LIMIT as i32).contains(&length),
            "oversized device frame"
        );
        Ok((kind, stream, length as usize))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            (1..=8).contains(&self.kind) && self.stream >= 0 && self.body.len() <= PAYLOAD_LIMIT,
            "invalid device frame"
        );
        let mut bytes = Vec::with_capacity(9 + self.body.len());
        bytes.push(self.kind);
        bytes.extend(self.stream.to_le_bytes());
        bytes.extend((self.body.len() as u32).to_le_bytes());
        bytes.extend(&self.body);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (kind, stream, length) = Self::header(bytes)?;
        ensure!(
            bytes.len() == 9 + length,
            "truncated or trailing device frame"
        );
        Ok(Self {
            kind,
            stream,
            body: bytes[9..].to_vec(),
        })
    }
}
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    session_window_bytes: u32,
    stream_window_bytes: u32,
    max_file_streams: u32,
}
impl Plan {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.session_window_bytes > 0
                && self.session_window_bytes <= 16 * 1024 * 1024
                && self.stream_window_bytes > 0
                && self.stream_window_bytes <= self.session_window_bytes
                && (1..=256).contains(&self.max_file_streams),
            "invalid device window plan"
        );
        Ok(())
    }
    fn capacity(&self) -> usize {
        (self.session_window_bytes as usize)
            .div_ceil(PAYLOAD_LIMIT)
            .clamp(1, 64)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    send_plan: Plan,
    receive_plan: Plan,
    is_client: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    operation: String,
    #[serde(default)]
    stream_id: i32,
    #[serde(default)]
    payload: Vec<i8>,
    #[serde(default)]
    value: i32,
}
struct State {
    streams: HashSet<i32>,
    pending: HashMap<i32, (Vec<u8>, bool)>,
    routes: HashMap<i32, watch::Sender<Route>>,
    transfers: HashMap<i32, CancellationToken>,
    in_flight: HashMap<i32, u32>,
    total: u32,
    next: i32,
    last: i32,
    pings: HashMap<Vec<u8>, Vec<oneshot::Sender<Vec<u8>>>>,
}
#[derive(Clone)]
enum Route {
    Pending,
    Active(mpsc::Sender<Result<Vec<u8>>>, bool),
    Discard,
}
#[derive(Clone, PartialEq, prost::Message)]
struct StreamOpen {
    #[prost(string, tag = "1")]
    kind: String,
}
pub struct Transport {
    state: Mutex<State>,
    plan: Plan,
    cancel: CancellationToken,
    outgoing: mpsc::Sender<Frame>,
    bodies: tokio::sync::Mutex<mpsc::Receiver<Frame>>,
    changed: watch::Sender<u64>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) max_transfers: usize,
    pub(crate) stream_capacity: usize,
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().unwrap().take() {
            task.abort();
        }
    }
}
struct Credit<'a> {
    transport: &'a Transport,
    stream: i32,
    bytes: u32,
    committed: bool,
}
impl Drop for Credit<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.transport.grant(self.stream, self.bytes);
        }
    }
}
impl Transport {
    fn active(&self) -> Result<()> {
        ensure!(
            !self.cancel.is_cancelled(),
            ResourceUnavailable("device transport closed")
        );
        Ok(())
    }
    async fn send(&self, frame: Frame) -> Result<()> {
        self.active()?;
        ensure!(
            frame.body.len() <= PAYLOAD_LIMIT,
            "device payload too large"
        );
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(ResourceUnavailable("device transport closed").into()),r=self.outgoing.send(frame)=>r.map_err(|_|ResourceUnavailable("device transport closed").into())}
    }
    fn grant(&self, stream: i32, bytes: u32) {
        let mut state = self.state.lock().unwrap();
        let used = state.in_flight.get(&stream).copied().unwrap_or(0);
        let released = used.min(bytes);
        state.total -= released;
        if used == released {
            state.in_flight.remove(&stream);
        } else {
            state.in_flight.insert(stream, used - released);
        }
        drop(state);
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
    fn remove(&self, stream: i32, retain_pending: bool) {
        {
            let mut state = self.state.lock().unwrap();
            state.streams.remove(&stream);
            // The browser may request start only after a native receive has completed.
            if !retain_pending {
                state.pending.remove(&stream);
            }
        }
        self.grant(stream, u32::MAX);
    }
    fn accept(&self, stream: i32) -> Result<bool> {
        self.active()?;
        let mut state = self.state.lock().unwrap();
        if !state.streams.contains(&stream) && state.streams.len() >= 256 {
            return Ok(false);
        }
        state.streams.insert(stream);
        state.last = state.last.max(stream);
        Ok(true)
    }
    pub async fn data(&self, stream: i32, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return self.data_frame(stream, vec![]).await;
        }
        for chunk in payload.chunks(PAYLOAD_LIMIT) {
            self.data_frame(stream, chunk.to_vec()).await?;
        }
        Ok(())
    }
    async fn data_frame(&self, stream: i32, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            bytes.len() <= self.plan.stream_window_bytes as usize,
            "frame exceeds stream window"
        );
        let mut version = self.changed.subscribe();
        let wait = async {
            loop {
                version.borrow_and_update();
                self.active()?;
                let ready = {
                    let mut state = self.state.lock().unwrap();
                    ensure!(
                        state.streams.contains(&stream),
                        ResourceUnavailable("device stream closed")
                    );
                    let used = state.in_flight.get(&stream).copied().unwrap_or(0);
                    let size = bytes.len() as u32;
                    if size <= self.plan.stream_window_bytes - used
                        && size <= self.plan.session_window_bytes - state.total
                    {
                        state.in_flight.insert(stream, used + size);
                        state.total += size;
                        true
                    } else {
                        false
                    }
                };
                if ready {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::select! {_=self.cancel.cancelled()=>return Err(ResourceUnavailable("device transport closed").into()),changed=version.changed()=>changed?,}
            }
        };
        tokio::time::timeout(Duration::from_secs(120), wait)
            .await
            .context("device stream credit timeout")??;
        let mut credit = Credit {
            transport: self,
            stream,
            bytes: bytes.len() as u32,
            committed: false,
        };
        ensure!(
            self.state.lock().unwrap().streams.contains(&stream),
            ResourceUnavailable("device stream closed")
        );
        self.send(Frame {
            kind: 3,
            stream,
            body: bytes,
        })
        .await?;
        credit.committed = true;
        Ok(())
    }

    pub(crate) fn register_transfer(
        &self,
        stream: i32,
        receiving: bool,
        cancel: CancellationToken,
        input: mpsc::Sender<Result<Vec<u8>>>,
        archive: bool,
    ) -> Result<()> {
        self.active()?;
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.transfers.contains_key(&stream),
            "stream already has a transfer"
        );
        ensure!(
            state.transfers.len() < self.max_transfers,
            ResourceUnavailable("device transfer capacity reached")
        );
        state.transfers.insert(stream, cancel);
        if receiving {
            let route = state
                .routes
                .entry(stream)
                .or_insert_with(|| watch::channel(Route::Pending).0);
            route.send_replace(Route::Active(input, archive));
        }
        Ok(())
    }
    pub(crate) fn release_transfer(&self, stream: i32) {
        let mut state = self.state.lock().unwrap();
        if let Some(cancel) = state.transfers.remove(&stream) {
            cancel.cancel();
        }
        if let Some(route) = state.routes.get(&stream) {
            route.send_replace(Route::Discard);
        }
    }
    pub(crate) async fn start_pending(&self, stream: i32) -> Result<()> {
        let payload = {
            let mut state = self.state.lock().unwrap();
            state
                .pending
                .get_mut(&stream)
                .filter(|(_, sent)| !*sent)
                .map(|(payload, sent)| {
                    *sent = true;
                    payload.clone()
                })
        };
        if let Some(payload) = payload {
            self.send(Frame {
                kind: 2,
                stream,
                body: payload,
            })
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn window(&self, stream: i32, bytes: usize) -> Result<()> {
        self.send(Frame {
            kind: 1,
            stream,
            body: (bytes as i32).to_le_bytes().to_vec(),
        })
        .await
    }
    pub(crate) async fn reset(&self, stream: i32) -> Result<()> {
        self.remove(stream, false);
        self.send(Frame {
            kind: 5,
            stream,
            body: 0i32.to_le_bytes().to_vec(),
        })
        .await
    }
    pub(crate) fn stopped(&self) -> CancellationToken {
        self.cancel.clone()
    }
    async fn route_body(&self, frame: Frame, bodies: &mpsc::Sender<Frame>) -> Result<bool> {
        let route = self
            .state
            .lock()
            .unwrap()
            .routes
            .get(&frame.stream)
            .map(|v| v.subscribe());
        let Some(mut route) = route else {
            bodies.send(frame).await.context("device body closed")?;
            return Ok(false);
        };
        loop {
            let target = route.borrow_and_update().clone();
            match target {
                Route::Pending => route.changed().await?,
                Route::Discard => return Ok(true),
                Route::Active(input, archive) => {
                    let size = frame.body.len();
                    if input.send(Ok(frame.body)).await.is_err() {
                        if archive {
                            self.window(frame.stream, size).await?;
                        } else {
                            let _ = self.reset(frame.stream).await;
                        }
                    }
                    return Ok(true);
                }
            }
        }
    }
    async fn operate(&self, input: Operation) -> Result<Reply> {
        ensure!(input.stream_id >= 0, "negative stream ID");
        let stream = input.stream_id;
        let mut payload = input
            .payload
            .into_iter()
            .map(|b| b as u8)
            .collect::<Vec<_>>();
        let mut result = json!({"streamId":0,"payload":[],"accepted":true});
        match input.operation.as_str() {
            "allocate" => {
                ensure!(payload.len() <= PAYLOAD_LIMIT, "OPEN payload too large");
                self.active()?;
                let mut state = self.state.lock().unwrap();
                ensure!(
                    state.streams.len() < 256 && state.pending.len() < 256,
                    ResourceUnavailable("device stream limit reached")
                );
                let id = state.next;
                ensure!(id > 0 && id <= i32::MAX - 2, "device stream IDs exhausted");
                state.next += 2;
                state.last = state.last.max(id);
                state.streams.insert(id);
                state.pending.insert(id, (payload, false));
                result["streamId"] = json!(id);
            }
            "start" => {
                let (payload, sent) = self
                    .state
                    .lock()
                    .unwrap()
                    .pending
                    .remove(&stream)
                    .context("unknown pending stream")?;
                if !sent {
                    if let Err(error) = self
                        .send(Frame {
                            kind: 2,
                            stream,
                            body: payload,
                        })
                        .await
                    {
                        self.remove(stream, false);
                        return Err(error);
                    }
                }
            }
            "accept" => result["accepted"] = json!(self.accept(stream)?),
            "control-frame" => {
                self.send(Frame {
                    kind: 3,
                    stream: 0,
                    body: payload,
                })
                .await?
            }
            "trailer" => {
                payload.truncate(PAYLOAD_LIMIT);
                self.send(Frame {
                    kind: 4,
                    stream,
                    body: payload,
                })
                .await?;
                self.remove(stream, true);
            }
            "window" => {
                ensure!(input.value >= 0, "negative window credit");
                self.send(Frame {
                    kind: 1,
                    stream,
                    body: input.value.to_le_bytes().to_vec(),
                })
                .await?;
            }
            "reset" => {
                {
                    let mut state = self.state.lock().unwrap();
                    if let Some(cancel) = state.transfers.get(&stream) {
                        cancel.cancel();
                    }
                    state.routes.remove(&stream);
                }
                self.remove(stream, false);
                self.send(Frame {
                    kind: 5,
                    stream,
                    body: input.value.to_le_bytes().to_vec(),
                })
                .await?;
            }
            "ping" => {
                payload.truncate(PAYLOAD_LIMIT);
                let (tx, rx) = oneshot::channel();
                self.active()?;
                {
                    let mut state = self.state.lock().unwrap();
                    state.pings.retain(|_, waiters| {
                        waiters.retain(|waiter| !waiter.is_closed());
                        !waiters.is_empty()
                    });
                    ensure!(
                        state.pings.len() < crate::management::session::REQUEST_LIMIT,
                        ResourceUnavailable("device ping capacity reached")
                    );
                    state.pings.entry(payload.clone()).or_default().push(tx);
                }
                self.send(Frame {
                    kind: 6,
                    stream: 0,
                    body: payload,
                })
                .await?;
                let payload = tokio::select! {_=self.cancel.cancelled()=>return Err(ResourceUnavailable("device transport closed").into()),r=rx=>r?};
                result["payload"] = json!(payload.iter().map(|v| *v as i8).collect::<Vec<_>>());
            }
            "go-away" => {
                let last = self.state.lock().unwrap().last;
                self.send(Frame {
                    kind: 8,
                    stream: 0,
                    body: last.to_le_bytes().to_vec(),
                })
                .await?;
                // Let the ordered writer flush GOAWAY before ending this connection.
            }
            _ => anyhow::bail!("unknown device transport operation"),
        }
        Ok(Reply::json(result))
    }
}
fn emit(session: &Weak<Session>, handle: &str, frame: Frame) -> Result<()> {
    let session = session.upgrade().context("session closed")?;
    session.emit(handle, "device-frames", frame.encode()?, false)?;
    Ok(())
}
fn start(
    channel: &Arc<Channel>,
    session: &Arc<Session>,
    handle: String,
    options: Open,
) -> Result<Arc<Transport>> {
    options.send_plan.validate()?;
    options.receive_plan.validate()?;
    let (outgoing, mut output) = mpsc::channel::<Frame>(options.send_plan.capacity());
    let (bodies, receiver) = mpsc::channel(options.receive_plan.capacity());
    let (changed, _) = watch::channel(0);
    let transport = Arc::new(Transport {
        state: Mutex::new(State {
            streams: HashSet::new(),
            pending: HashMap::new(),
            routes: HashMap::new(),
            transfers: HashMap::new(),
            in_flight: HashMap::new(),
            total: 0,
            next: if options.is_client { 1 } else { 2 },
            last: 0,
            pings: HashMap::new(),
        }),
        max_transfers: options
            .send_plan
            .max_file_streams
            .min(options.receive_plan.max_file_streams) as usize,
        stream_capacity: (options.receive_plan.stream_window_bytes as usize)
            .div_ceil(PAYLOAD_LIMIT)
            .clamp(1, 64),
        plan: options.send_plan,
        cancel: channel.cancel.clone(),
        outgoing,
        bodies: tokio::sync::Mutex::new(receiver),
        changed,
        task: Mutex::new(None),
    });
    let read = channel.read.clone();
    let write = channel.write.clone();
    let owner = Arc::downgrade(session);
    let cancel = channel.cancel.clone();
    let t = transport.clone();
    let task = tokio::spawn(async move {
        let reader = async {
            let mut reader = read.lock().await;
            loop {
                let mut header = [0u8; 9];
                reader.read_exact(&mut header).await?;
                let (kind, stream, size) = Frame::header(&header)?;
                let mut body = vec![0u8; size];
                reader.read_exact(&mut body).await?;
                let frame = Frame { kind, stream, body };
                match kind {
                    1 => {
                        let credit = if size >= 4 {
                            i32::from_le_bytes(frame.body[..4].try_into()?)
                        } else {
                            0
                        };
                        ensure!(credit >= 0, "negative window credit");
                        t.grant(stream, credit as u32);
                    }
                    2 => {
                        if t.accept(stream)? {
                            use prost::Message;
                            if let Ok(open) = StreamOpen::decode(frame.body.as_slice()) {
                                if matches!(open.kind.as_str(), "Write" | "ArchiveWrite") {
                                    t.state
                                        .lock()
                                        .unwrap()
                                        .routes
                                        .entry(stream)
                                        .or_insert_with(|| watch::channel(Route::Pending).0);
                                }
                            }
                            emit(&owner, &handle, frame)?;
                        } else {
                            t.send(Frame {
                                kind: 5,
                                stream,
                                body: 1i32.to_le_bytes().to_vec(),
                            })
                            .await?;
                        }
                    }
                    3 if stream != 0 => {
                        if !t.route_body(frame, &bodies).await? {
                            emit(
                                &owner,
                                &handle,
                                Frame {
                                    kind,
                                    stream,
                                    body: vec![],
                                },
                            )?;
                        }
                    }
                    4 | 5 => {
                        let route = t.state.lock().unwrap().routes.remove(&stream);
                        if kind == 5 {
                            if let Some(route) = &route {
                                let target = route.borrow().clone();
                                if let Route::Active(input, _) = target {
                                    let _ = input
                                        .send(
                                            Err(ResourceUnavailable("device stream reset").into()),
                                        )
                                        .await;
                                }
                            }
                        }
                        drop(route);
                        t.remove(stream, true);
                        emit(&owner, &handle, frame)?;
                    }
                    6 => {
                        emit(&owner, &handle, frame.clone())?;
                        t.send(Frame {
                            kind: 7,
                            stream: 0,
                            body: frame.body,
                        })
                        .await?;
                    }
                    7 => {
                        let waiters = t
                            .state
                            .lock()
                            .unwrap()
                            .pings
                            .remove(&frame.body)
                            .unwrap_or_default();
                        for tx in waiters {
                            let _ = tx.send(frame.body.clone());
                        }
                    }
                    8 => {
                        emit(&owner, &handle, frame)?;
                        return Ok::<(), anyhow::Error>(());
                    }
                    _ => emit(&owner, &handle, frame)?,
                }
            }
        };
        let writer = async {
            let mut writer = write.lock().await;
            while let Some(frame) = output.recv().await {
                writer.write_all(&frame.encode()?).await?;
                writer.flush().await?;
                if frame.kind == 8 {
                    return Ok::<(), anyhow::Error>(());
                }
            }
            Ok(())
        };
        tokio::select! {_=cancel.cancelled()=>{},_=reader=>{},_=writer=>{}}
        cancel.cancel();
        {
            let mut state = t.state.lock().unwrap();
            for stop in state.transfers.values() {
                stop.cancel();
            }
            state.routes.clear();
        }
        t.changed.send_modify(|v| *v = v.wrapping_add(1));
        t.state.lock().unwrap().pings.clear();
        if let Some(session) = owner.upgrade() {
            let _ = session.emit(&handle, "device-end", vec![], false);
        }
    });
    *transport.task.lock().unwrap() = Some(task);
    Ok(transport)
}
pub async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
) -> Result<Reply> {
    ensure!(body.len() <= BODY_LIMIT, "device request too large");
    let (_, query) = raw.split_once('?').unwrap_or((raw, ""));
    let query = crate::management::wire::query(query);
    let handle = query.get("handle").context("device handle required")?;
    let channel = session.resource::<Channel>(handle)?;
    let operation = query.get("operation").map(String::as_str);
    if method == "POST" && operation.is_none() {
        let options: Open = serde_json::from_slice(&body)?;
        // Raw reads and transport initialization share the same gate.
        let _gate = channel.read.lock().await;
        let mut current = channel.transport.lock().unwrap();
        ensure!(current.is_none(), "device transport already started");
        let transport = start(&channel, session, handle.clone(), options)?;
        *current = Some(transport);
        let mut reply = Reply::json(true);
        reply
            .headers
            .insert("x-folderspan-device-feedback-timing".into(), "1".into());
        reply.headers.insert(
            "x-folderspan-host-time".into(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .to_string(),
        );
        return Ok(reply);
    }
    let transport = channel
        .transport
        .lock()
        .unwrap()
        .clone()
        .context("device transport not started")?;
    match (method, operation) {
        ("POST", Some("control")) => {
            let input: Operation = serde_json::from_slice(&body)?;
            ensure!(input.operation != "data", "file body requires HTTP");
            transport.operate(input).await
        }
        ("POST", Some("data")) => {
            let stream = query
                .get("streamId")
                .context("stream ID required")?
                .parse::<i32>()?;
            ensure!(stream >= 0, "negative stream ID");
            transport.data(stream, &body).await?;
            Ok(Reply::json(
                json!({"streamId":0,"payload":[],"accepted":true}),
            ))
        }
        ("GET", Some("body")) => {
            let stream = query
                .get("streamId")
                .context("stream ID required")?
                .parse::<i32>()?;
            let mut bodies = transport.bodies.lock().await;
            let frame = tokio::select! {_=transport.cancel.cancelled()=>return Err(ResourceUnavailable("device transport closed").into()),r=bodies.recv()=>r.context("device body ended")?};
            ensure!(frame.stream == stream, "device body stream order mismatch");
            Ok(Reply::bytes(frame.body))
        }
        _ => Ok(Reply::error(
            404,
            "not_found",
            "unknown device stream operation",
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_encoding_is_little_endian_and_bounded() {
        let frame = Frame {
            kind: 3,
            stream: 0x10203,
            body: vec![0, 128, 255],
        };
        assert_eq!(
            frame.encode().unwrap(),
            vec![3, 3, 2, 1, 0, 3, 0, 0, 0, 0, 128, 255]
        );
        assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
        assert!(Frame::decode(&[2; 8]).is_err());
        for (kind, stream, length) in [(9u8, 0i32, 0i32), (1, -1, 0), (1, 0, -1), (1, 0, 65537)] {
            let mut bytes = vec![kind];
            bytes.extend(stream.to_le_bytes());
            bytes.extend(length.to_le_bytes());
            assert!(Frame::decode(&bytes).is_err());
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_queued_frame_returns_reserved_credit() {
        let (outgoing, _receiver) = mpsc::channel(1);
        let (_, bodies) = mpsc::channel(1);
        let (changed, _) = watch::channel(0);
        outgoing
            .try_send(Frame {
                kind: 3,
                stream: 0,
                body: vec![],
            })
            .unwrap();
        let t = Arc::new(Transport {
            state: Mutex::new(State {
                streams: HashSet::from([1]),
                pending: HashMap::new(),
                routes: HashMap::new(),
                transfers: HashMap::new(),
                in_flight: HashMap::new(),
                total: 0,
                next: 3,
                last: 1,
                pings: HashMap::new(),
            }),
            plan: Plan {
                session_window_bytes: 65536,
                stream_window_bytes: 65536,
                max_file_streams: 1,
            },
            cancel: CancellationToken::new(),
            outgoing,
            bodies: tokio::sync::Mutex::new(bodies),
            changed,
            task: Mutex::new(None),
            max_transfers: 1,
            stream_capacity: 1,
        });
        let copy = t.clone();
        let task = tokio::spawn(async move { copy.data(1, &[1; 100]).await });
        for _ in 0..100 {
            if t.state.lock().unwrap().total == 100 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(t.state.lock().unwrap().total, 100);
        task.abort();
        let _ = task.await;
        assert_eq!(t.state.lock().unwrap().total, 0);
    }
}
