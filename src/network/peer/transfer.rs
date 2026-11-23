use crate::{
    management::{
        reply::{Reply, ResourceUnavailable},
        session::Session,
    },
    network::peer::{
        devices::Channel,
        transport::{PAYLOAD_LIMIT, Transport},
    },
    storage::files::FilePolicy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    stream_id: i32,
    kind: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    file_size: i64,
    #[serde(default)]
    start_offset: i64,
    #[serde(default)]
    end_offset: i64,
    #[serde(default)]
    archive_read: Option<crate::storage::archive::ReadRequest>,
    #[serde(default)]
    archive_write: Option<crate::storage::archive::WriteRequest>,
    #[serde(default)]
    callback_id: String,
    #[serde(default)]
    target_handle: String,
    #[serde(default)]
    target_stream_id: i32,
    #[serde(default)]
    progress_callback_id: String,
    #[serde(default)]
    initially_paused: bool,
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult {
    pub completed_relative_paths: Vec<String>,
    pub committed_file_bytes: u64,
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    complete: bool,
    progress: BTreeMap<String, u64>,
    result: TransferResult,
    error: String,
}
#[derive(Clone)]
pub(crate) struct Transfer {
    pub(crate) transport: Arc<Transport>,
    request: Request,
    pub(crate) state: Arc<Mutex<Status>>,
    running: watch::Sender<bool>,
    cancel: CancellationToken,
}
impl Transfer {
    pub(crate) async fn running(&self) -> Result<()> {
        let mut running = self.running.subscribe();
        while !*running.borrow_and_update() {
            tokio::select! {_=self.cancel.cancelled()=>return Err(ResourceUnavailable("device transfer cancelled").into()),r=running.changed()=>r?,}
        }
        Ok(())
    }
    pub(crate) fn progress(&self, path: &str, bytes: usize) {
        *self
            .state
            .lock()
            .unwrap()
            .progress
            .entry(path.into())
            .or_default() += bytes as u64;
    }
    pub(crate) fn stream(&self) -> i32 {
        self.request.stream_id
    }
    pub(crate) fn committed(&self, result: TransferResult) {
        self.state.lock().unwrap().result = result;
    }
    pub(crate) async fn prepare(
        &self,
        session: &Session,
        files: &FilePolicy,
        path: &Path,
        size: u64,
        directory: bool,
    ) -> Result<()> {
        files.check_write(path, session)?;
        if !self.request.callback_id.is_empty() {
            session
                .callback(
                    &self.request.callback_id,
                    "device-prepare-entry",
                    serde_json::to_vec(&json!({"path":path,"size":size,"directory":directory}))?,
                )
                .await?;
        }
        Ok(())
    }
    async fn file_send(&self, session: &Session, files: &FilePolicy) -> Result<TransferResult> {
        let r = &self.request;
        let mut file = files
            .open(Path::new(&r.path), session, false, false, false)?
            .into_std();
        file.seek(SeekFrom::Start(r.start_offset as u64))?;
        let mut remaining = (r.end_offset - r.start_offset) as u64;
        let mut buffer = vec![0; PAYLOAD_LIMIT];
        while remaining > 0 {
            self.running().await?;
            let size = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..size])?;
            self.transport.data(r.stream_id, &buffer[..size]).await?;
            remaining -= size as u64;
            self.progress(&r.path, size);
        }
        Ok(TransferResult {
            completed_relative_paths: vec![r.path.clone()],
            committed_file_bytes: (r.end_offset - r.start_offset) as u64,
        })
    }
    async fn file_receive(
        &self,
        session: &Session,
        files: &FilePolicy,
        mut input: mpsc::Receiver<Result<Vec<u8>>>,
    ) -> Result<TransferResult> {
        let r = &self.request;
        let mut target = files.receive_target(Path::new(&r.path), session)?;
        if r.file_size == 0 {
            target.file.set_len(0)?;
        } else if target.file.metadata()?.len() < r.file_size as u64 {
            target.file.set_len(r.file_size as u64)?;
        }
        target.file.seek(SeekFrom::Start(r.start_offset as u64))?;
        let expected = (r.end_offset - r.start_offset) as u64;
        let mut received = 0u64;
        while let Some(next) = input.recv().await {
            self.running().await?;
            let bytes = next?;
            ensure!(
                bytes.len() as u64 <= expected - received,
                "device file stream exceeds declared range"
            );
            target.file.write_all(&bytes)?;
            received += bytes.len() as u64;
            self.progress(&r.path, bytes.len());
            self.transport.window(r.stream_id, bytes.len()).await?;
        }
        ensure!(received == expected, "incomplete device file stream");
        target.file.flush()?;
        target.commit();
        Ok(TransferResult {
            completed_relative_paths: vec![r.path.clone()],
            committed_file_bytes: received,
        })
    }
    async fn relay(
        &self,
        session: &Session,
        mut input: mpsc::Receiver<Result<Vec<u8>>>,
    ) -> Result<TransferResult> {
        let r = &self.request;
        let target = session.resource::<Channel>(&r.target_handle)?;
        let target = target
            .transport
            .lock()
            .unwrap()
            .clone()
            .context("relay target transport not started")?;
        target.start_pending(r.target_stream_id).await?;
        if let Some(read) = &r.archive_read {
            return crate::storage::archive::relay(
                self,
                &target,
                r.target_stream_id,
                input,
                &read.options,
            )
            .await;
        }
        let mut received = 0u64;
        while let Some(chunk) = input.recv().await {
            self.running().await?;
            let chunk = chunk?;
            target.data(r.target_stream_id, &chunk).await?;
            received += chunk.len() as u64;
            self.transport.window(r.stream_id, chunk.len()).await?;
            self.progress(&r.path, chunk.len());
        }
        ensure!(
            received == (r.end_offset - r.start_offset) as u64,
            "relay stream length mismatch"
        );
        Ok(TransferResult {
            completed_relative_paths: vec![],
            committed_file_bytes: received,
        })
    }
    async fn run(
        &self,
        session: &Session,
        files: &FilePolicy,
        input: mpsc::Receiver<Result<Vec<u8>>>,
    ) -> Result<TransferResult> {
        match self.request.kind.as_str() {
            "SendFile" => self.file_send(session, files).await,
            "ReceiveFile" => self.file_receive(session, files, input).await,
            "Relay" => self.relay(session, input).await,
            "SendArchive" => {
                crate::storage::archive::send(
                    self,
                    session,
                    files,
                    self.request
                        .archive_read
                        .as_ref()
                        .context("archive read plan required")?,
                )
                .await
            }
            "ReceiveArchive" => {
                crate::storage::archive::receive(
                    self,
                    session,
                    files,
                    input,
                    self.request
                        .archive_write
                        .as_ref()
                        .context("archive write plan required")?,
                )
                .await
            }
            _ => anyhow::bail!("unknown device transfer kind"),
        }
    }
}
pub async fn open(
    body: Vec<u8>,
    session: &Arc<Session>,
    channel: &Arc<Channel>,
    files: Arc<FilePolicy>,
) -> Result<Reply> {
    let r: Request = serde_json::from_slice(&body)?;
    ensure!(
        r.stream_id > 0 && r.callback_id.len() <= 128 && r.progress_callback_id.len() <= 128,
        "invalid transfer"
    );
    ensure!(
        matches!(
            r.kind.as_str(),
            "SendFile" | "ReceiveFile" | "Relay" | "SendArchive" | "ReceiveArchive"
        ),
        "unsupported device transfer kind"
    );
    ensure!(
        r.start_offset >= 0 && r.end_offset >= r.start_offset,
        "invalid transfer range"
    );
    if matches!(r.kind.as_str(), "SendFile" | "ReceiveFile") {
        ensure!(
            r.file_size >= 0 && r.end_offset <= r.file_size,
            "invalid file transfer range"
        );
        if r.kind == "ReceiveFile" {
            files.check_write(Path::new(&r.path), session)?;
        } else {
            files.check(Path::new(&r.path), session)?;
        }
    } else if r.kind == "SendArchive" {
        crate::storage::archive::validate_read(
            r.archive_read
                .as_ref()
                .context("archive read plan required")?,
            session,
            &files,
        )?;
    } else if r.kind == "ReceiveArchive" {
        crate::storage::archive::validate_write(
            r.archive_write
                .as_ref()
                .context("archive write plan required")?,
            session,
            &files,
        )?;
    } else {
        ensure!(r.target_stream_id > 0, "invalid relay target");
        let target = session.resource::<Channel>(&r.target_handle)?;
        ensure!(
            target.transport.lock().unwrap().is_some(),
            "relay target transport not started"
        );
    }
    let transport = channel
        .transport
        .lock()
        .unwrap()
        .clone()
        .context("device transport not started")?;
    let receiving = matches!(r.kind.as_str(), "ReceiveFile" | "ReceiveArchive" | "Relay");
    let (sender, input) = mpsc::channel(transport.stream_capacity);
    let cancel = CancellationToken::new();
    let (running, _) = watch::channel(!r.initially_paused);
    let stream = r.stream_id;
    let transfer = Transfer {
        transport: transport.clone(),
        request: r,
        state: Arc::new(Mutex::new(Status::default())),
        running,
        cancel: cancel.clone(),
    };
    transport.register_transfer(
        stream,
        receiving,
        cancel.clone(),
        sender,
        transfer.request.kind == "ReceiveArchive",
    )?;
    let worker = transfer.clone();
    let owner = Arc::downgrade(session);
    let (start, started) = tokio::sync::oneshot::channel();
    let runtime = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        runtime.block_on(async move{
        if started.await.is_err(){return;}
        let Some(session)=owner.upgrade()else{return;};
        let parent=worker.transport.stopped();let session_stop=session.cancel.clone();
        let work=async {
            worker.transport.start_pending(stream).await?;
            worker.run(&session,&files,input).await
        };
        let reporter=async {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if !worker.request.progress_callback_id.is_empty() {
                    let status=worker.state.lock().unwrap().clone();
                    session.emit_latest(&worker.request.progress_callback_id,"device-progress",serde_json::to_vec(&status)?,false)?;
                }
            }
            #[allow(unreachable_code)] Ok::<(),anyhow::Error>(())
        };
        let result=tokio::select! {
            biased;
            _=worker.cancel.cancelled()=>Err(ResourceUnavailable("device transfer cancelled").into()),
            _=parent.cancelled()=>Err(ResourceUnavailable("device transport closed").into()),
            _=session_stop.cancelled()=>Err(ResourceUnavailable("session closed").into()),
            r=work=>r,
            r=reporter=>{r.and_then(|_|Err(anyhow::anyhow!("progress reporting ended")))}
        };
        let failed=result.is_err();
        {let mut status=worker.state.lock().unwrap();match result {
            Ok(result)=>status.result=result,
            Err(_)=>status.error="device file transfer failed".into(),
        }status.complete=true;}
        if failed && (worker.request.kind!="ReceiveArchive" || worker.cancel.is_cancelled() || parent.is_cancelled() || session_stop.is_cancelled()) {let _=worker.transport.reset(stream).await;}
        if !worker.request.progress_callback_id.is_empty() {
            let status=worker.state.lock().unwrap().clone();
            let _=session.emit_latest(&worker.request.progress_callback_id,"device-progress",serde_json::to_vec(&status).unwrap(),true);
        }
    })
    });
    let close_transport = transport.clone();
    let close = cancel.clone();
    let id = session.own_with_wait(
        transfer,
        move || {
            close.cancel();
            close_transport.release_transfer(stream);
        },
        task,
    )?;
    let _ = start.send(());
    Ok(Reply::json(json!({"id":id})))
}
pub async fn status(method: &str, raw: &str, session: &Arc<Session>) -> Result<Reply> {
    let (_, query) = raw.split_once('?').unwrap_or((raw, ""));
    let query = crate::management::wire::query(query);
    let transfer =
        session.resource::<Transfer>(query.get("handle").context("transfer handle required")?)?;
    let pause = query.get("pause").is_some_and(|v| v == "true");
    match method {
        "GET" => {
            if pause {
                transfer.running.send_replace(false);
            }
            Ok(Reply::json(serde_json::to_value(
                transfer.state.lock().unwrap().clone(),
            )?))
        }
        "POST" => {
            transfer.running.send_replace(!pause);
            Ok(Reply::json(true))
        }
        _ => Ok(Reply::error(
            404,
            "not_found",
            "unknown device transfer operation",
        )),
    }
}
