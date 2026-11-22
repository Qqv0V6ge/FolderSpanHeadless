use crate::{
    management::{
        reply::{PlatformFailure, Reply, ResourceUnavailable},
        session::Session,
        wire::BODY_LIMIT,
    },
    network::tls_client::fingerprint_config,
};
use anyhow::{Context, Result, ensure};
use futures_util::{StreamExt, stream};
use reqwest::{
    Client, Method,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::AbortHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPair {
    pub first: String,
    pub second: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientOpen {
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    capture_certificate: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutgoingRequest {
    client: String,
    url: String,
    method: String,
    headers: Vec<HeaderPair>,
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    content_length: Option<i64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct IncomingResponse {
    status: u16,
    headers: Vec<HeaderPair>,
    fingerprint: Option<String>,
}
struct HttpClient {
    client: Client,
    pin: bool,
    capture: bool,
    serial: Mutex<()>,
    cancel: CancellationToken,
}
#[derive(Clone, Copy, Debug)]
enum Failure {
    Network,
    Closed,
}
impl Failure {
    fn error(self) -> anyhow::Error {
        match self {
            Self::Network => PlatformFailure.into(),
            Self::Closed => ResourceUnavailable("HTTP transfer closed").into(),
        }
    }
}
struct Upload {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    written: u64,
}
struct Transfer {
    input: Mutex<Upload>,
    output: Mutex<mpsc::Receiver<std::result::Result<Vec<u8>, Failure>>>,
    metadata: watch::Receiver<Option<std::result::Result<IncomingResponse, Failure>>>,
    expected: Option<u64>,
    cancel: CancellationToken,
    task: AbortHandle,
}
impl Drop for Transfer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
impl Drop for HttpClient {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
fn make_client(input: ClientOpen) -> Result<HttpClient> {
    ensure!(
        input
            .fingerprint
            .as_ref()
            .is_none_or(|p| !p.trim().is_empty())
            && !(input.capture_certificate && input.fingerprint.is_some()),
        "invalid certificate configuration"
    );
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(300))
        .timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(if input.capture_certificate { 0 } else { 64 })
        .tls_info(true)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd();
    if input.fingerprint.is_some() || input.capture_certificate {
        builder = builder.use_preconfigured_tls(fingerprint_config(input.fingerprint.as_deref())?);
    }
    Ok(HttpClient {
        client: builder.build()?,
        pin: input.fingerprint.is_some(),
        capture: input.capture_certificate,
        serial: Mutex::new(()),
        cancel: CancellationToken::new(),
    })
}
pub async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
) -> Result<Reply> {
    ensure!(body.len() <= BODY_LIMIT, "HTTP body too large");
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let operation = path
        .strip_prefix("/api/web-ui/platform/http")
        .context("invalid HTTP route")?;
    if method == "POST" && operation == "/clients" {
        let client = make_client(serde_json::from_slice(&body)?)?;
        let close = client.cancel.clone();
        let id = session.own_with_close(client, move || close.cancel())?;
        return Ok(Reply::json(json!({"id":id})));
    }
    if method == "POST" && operation == "/requests" {
        let input: OutgoingRequest = serde_json::from_slice(&body)?;
        let client = session.resource::<HttpClient>(&input.client)?;
        let url = url::Url::parse(&input.url)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none(),
            "HTTP(S) URL without userinfo required"
        );
        ensure!(
            !client.pin || url.scheme() == "https",
            "pinned requests require HTTPS"
        );
        ensure!(
            !input.method.is_empty()
                && input
                    .method
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'-'),
            "invalid HTTP method"
        );
        ensure!(
            input.content_length.is_none_or(|v| v >= 0) && input.headers.len() <= 128,
            "invalid HTTP request"
        );
        let mut request = client
            .client
            .request(Method::from_bytes(input.method.as_bytes())?, url);
        for header in input.headers {
            let name = HeaderName::from_bytes(header.first.as_bytes())?;
            ensure!(
                !header.second.contains(['\r', '\n', '\0']),
                "invalid HTTP header"
            );
            let value = HeaderValue::from_str(&header.second)?;
            if !matches!(
                name.as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) {
                request = request.header(name, value);
            }
        }
        let expected = input.content_length.map(|v| v as u64);
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(1);
        if expected != Some(0) {
            let source = stream::unfold(input_rx, |mut input| async move {
                input
                    .recv()
                    .await
                    .map(|bytes| (Ok::<Vec<u8>, std::io::Error>(bytes), input))
            });
            request = request.body(reqwest::Body::wrap_stream(source));
            if let Some(length) = expected {
                request = request.header("content-length", length);
            }
        }
        let (output_tx, output) = mpsc::channel(1);
        let (metadata_tx, metadata) = watch::channel(None);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let session_stop = session.cancel.clone();
        let (start, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let result = tokio::select! {
                biased;
                _=stop.cancelled()=>Err(Failure::Closed),
                _=session_stop.cancelled()=>Err(Failure::Closed),
                _=client.cancel.cancelled()=>Err(Failure::Closed),
                result=async {
                    let _serial=if client.capture {Some(client.serial.lock().await)}else{None};
                    let response=request.send().await.map_err(|_|Failure::Network)?;
                    let fingerprint=if client.capture {
                        response.extensions().get::<reqwest::tls::TlsInfo>().and_then(|info|info.peer_certificate())
                            .map(|cert|hex::encode_upper(Sha256::digest(cert)))
                    }else{None};
                    let headers=response.headers().iter().map(|(name,value)|HeaderPair{first:name.to_string(),second:String::from_utf8_lossy(value.as_bytes()).into_owned()}).collect();
                    metadata_tx.send_replace(Some(Ok(IncomingResponse{status:response.status().as_u16(),headers,fingerprint})));
                    let mut source=response.bytes_stream();
                    while let Some(bytes)=source.next().await {
                        let bytes=bytes.map_err(|_|Failure::Network)?;
                        for part in bytes.chunks(64*1024) {
                            output_tx.send(Ok(part.to_vec())).await.map_err(|_|Failure::Closed)?;
                        }
                    }
                    Ok(())
                }=>result,
            };
            if let Err(failure) = result {
                if metadata_tx.borrow().is_none() {
                    metadata_tx.send_replace(Some(Err(failure)));
                }
                let _ = output_tx.send(Err(failure)).await;
            }
        });
        let abort = task.abort_handle();
        let close = cancel.clone();
        let close_task = abort.clone();
        let id = session.own_with_wait(
            Transfer {
                input: Mutex::new(Upload {
                    sender: Some(input_tx),
                    written: 0,
                }),
                output: Mutex::new(output),
                metadata,
                expected,
                cancel,
                task: abort,
            },
            move || {
                close.cancel();
                close_task.abort();
            },
            task,
        )?;
        let _ = start.send(());
        return Ok(Reply::json(json!({"id":id})));
    }
    let query = crate::management::wire::query(query);
    let transfer = session.resource::<Transfer>(query.get("handle").context("handle required")?)?;
    match (method, operation) {
        ("GET", "/response") => {
            let mut metadata = transfer.metadata.clone();
            loop {
                if let Some(result) = metadata.borrow().clone() {
                    return result.map(Reply::json).map_err(Failure::error);
                }
                tokio::select! {
                    biased;
                    _=transfer.cancel.cancelled()=>return Err(Failure::Closed.error()),
                    changed=metadata.changed()=>if changed.is_err(){return Err(Failure::Closed.error());},
                }
            }
        }
        ("PUT", "/upload") => {
            let mut input = transfer.input.lock().await;
            ensure!(
                transfer.expected.is_none_or(
                    |size| input.written <= size && body.len() as u64 <= size - input.written
                ),
                "HTTP upload length exceeded"
            );
            let sender = input.sender.as_ref().context("HTTP upload finished")?;
            let length = body.len();
            tokio::select! {
                biased;
                _=transfer.cancel.cancelled()=>return Err(Failure::Closed.error()),
                result=sender.send(body)=>result.map_err(|_|Failure::Closed.error())?,
            }
            input.written += length as u64;
            Ok(Reply::json(true))
        }
        ("POST", "/upload") => {
            let mut input = transfer.input.lock().await;
            ensure!(
                transfer.expected.is_none_or(|size| size == input.written),
                "incomplete HTTP upload"
            );
            input.sender.take();
            Ok(Reply::json(true))
        }
        ("GET", "/download") => {
            let mut output = transfer.output.lock().await;
            let part = tokio::select! {
                biased;
                _=transfer.cancel.cancelled()=>return Err(Failure::Closed.error()),
                part=output.recv()=>part,
            };
            let end = part.is_none();
            let mut reply = Reply::bytes(
                part.transpose()
                    .map_err(Failure::error)?
                    .unwrap_or_default(),
            );
            reply
                .headers
                .insert("x-folderspan-end".into(), end.to_string());
            Ok(reply)
        }
        _ => Ok(Reply::error(
            404,
            "not_found",
            "unknown outbound HTTP operation",
        )),
    }
}
