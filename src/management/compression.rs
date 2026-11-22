use crate::management::{reply::Reply, session::Session};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::{
    sync::{Mutex, mpsc},
    task::AbortHandle,
};
use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

struct Compression {
    input: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    output: Mutex<mpsc::Receiver<Result<Vec<u8>>>>,
    task: AbortHandle,
}
impl Drop for Compression {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn emit(output: &mpsc::Sender<Result<Vec<u8>>>, bytes: &[u8]) -> Result<()> {
    if !bytes.is_empty() {
        output
            .send(Ok(bytes.to_vec()))
            .await
            .map_err(|_| anyhow::anyhow!("compression stream closed"))?;
    }
    Ok(())
}
pub(crate) async fn transform<O: Operation>(
    mut op: O,
    decompress: bool,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: &mpsc::Sender<Result<Vec<u8>>>,
) -> Result<()> {
    let mut frame_complete = false;
    while let Some(bytes) = input.recv().await {
        ensure!(
            !decompress || !frame_complete || bytes.is_empty(),
            "trailing compressed archive data"
        );
        let bytes_len = bytes.len();
        let mut source = InBuffer::around(&bytes);
        while source.pos() < bytes.len() {
            let before = source.pos();
            let mut bytes = [0; 64 * 1024];
            let mut target = OutBuffer::around(&mut bytes);
            let remaining = op.run(&mut source, &mut target)?;
            let written = target.pos();
            ensure!(
                source.pos() > before || written > 0,
                "compression made no progress"
            );
            emit(output, &bytes[..written]).await?;
            if decompress && remaining == 0 {
                frame_complete = true;
                ensure!(
                    source.pos() == bytes_len,
                    "trailing compressed archive data"
                );
            }
        }
    }
    ensure!(
        !decompress || frame_complete,
        "compressed archive ended before the zstd frame completed"
    );
    loop {
        let mut bytes = [0; 64 * 1024];
        let mut target = OutBuffer::around(&mut bytes);
        let remaining = op.finish(&mut target, frame_complete)?;
        let written = target.pos();
        emit(output, &bytes[..written]).await?;
        if remaining == 0 {
            break;
        }
        ensure!(written > 0, "compression made no finish progress");
    }
    Ok(())
}
pub async fn handle(
    method: &str,
    raw: &str,
    body: Vec<u8>,
    session: &Arc<Session>,
) -> Result<Reply> {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    if method == "POST" && path == "/api/web-ui/platform/compression" {
        let v: Value = serde_json::from_slice(&body)?;
        let codec = v["codec"].as_u64().context("codec required")?;
        let decompress = v["decompress"].as_bool().context("decompress required")?;
        ensure!(
            codec == 0 || codec == 1,
            "unsupported archive compression codec"
        );
        let (input_tx, mut input) = mpsc::channel(1);
        let (output_tx, output) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let result = match codec {
                0 => {
                    let mut result = Ok(());
                    while let Some(bytes) = input.recv().await {
                        if output_tx.send(Ok(bytes)).await.is_err() {
                            result = Err(anyhow::anyhow!("compression stream closed"));
                            break;
                        }
                    }
                    result
                }
                _ if decompress => match zstd::stream::raw::Decoder::new() {
                    Ok(mut op) => {
                        match op.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(27)) {
                            Ok(()) => transform(op, true, input, &output_tx).await,
                            Err(e) => Err(e.into()),
                        }
                    }
                    Err(e) => Err(e.into()),
                },
                _ => match zstd::stream::raw::Encoder::new(1) {
                    Ok(op) => transform(op, false, input, &output_tx).await,
                    Err(e) => Err(e.into()),
                },
            };
            if let Err(e) = result {
                let _ = output_tx.send(Err(e)).await;
            }
        });
        let abort = task.abort_handle();
        let handle = session.own_with_wait(
            Compression {
                input: Mutex::new(Some(input_tx)),
                output: Mutex::new(output),
                task: task.abort_handle(),
            },
            move || abort.abort(),
            task,
        )?;
        return Ok(Reply::json(json!({"id":handle})));
    }
    let query = crate::management::wire::query(query);
    let id = query.get("handle").context("handle required")?;
    let stream = session.resource::<Compression>(id)?;
    match method {
        "PUT" => {
            let input = stream.input.lock().await;
            input
                .as_ref()
                .context("compression input finished")?
                .send(body)
                .await
                .map_err(|_| anyhow::anyhow!("compression worker stopped"))?;
            Ok(Reply::json(true))
        }
        "POST" => {
            stream.input.lock().await.take();
            Ok(Reply::json(true))
        }
        "GET" => {
            let mut output = stream.output.lock().await;
            let value = tokio::select! {_=session.cancel.cancelled()=>anyhow::bail!("session closed"),v=output.recv()=>v};
            let end = value.is_none();
            let mut r = Reply::bytes(value.transpose()?.unwrap_or_default());
            r.headers.insert("x-folderspan-end".into(), end.to_string());
            Ok(r)
        }
        _ => Ok(Reply::error(
            405,
            "invalid_argument",
            "invalid compression operation",
        )),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    async fn process(bytes: Vec<u8>, decompress: bool) -> Result<Vec<u8>> {
        let root = tempfile::tempdir()?;
        let session = Session::new(root.path())?;
        let response = handle(
            "POST",
            "/api/web-ui/platform/compression",
            serde_json::to_vec(&json!({"codec":1,"decompress":decompress}))?,
            &session,
        )
        .await?;
        let value: Value = serde_json::from_slice(&response.body)?;
        let id = value["id"].as_str().context("missing handle")?;
        let path = format!("/api/web-ui/platform/compression?handle={id}");
        let writer = {
            let session = session.clone();
            let path = path.clone();
            tokio::spawn(async move {
                for part in bytes.chunks(4096) {
                    handle("PUT", &path, part.to_vec(), &session).await?;
                }
                handle(
                    "POST",
                    &path.replace("/compression?", "/compression/finish?"),
                    vec![],
                    &session,
                )
                .await
            })
        };
        // The reader and writer run concurrently to exercise bounded backpressure.
        let mut result = vec![];
        loop {
            let r = handle("GET", &path, vec![], &session).await?;
            result.extend(r.body);
            if r.headers
                .get("x-folderspan-end")
                .is_some_and(|s| s == "true")
            {
                break;
            }
        }
        writer.await??;
        Ok(result)
    }
    #[tokio::test]
    async fn roundtrip_truncation_and_trailing_frame() {
        let bytes = vec![42; 2 * 1024 * 1024 + 17];
        let compressed = process(bytes.clone(), false).await.unwrap();
        assert_eq!(process(compressed.clone(), true).await.unwrap(), bytes);
        assert!(
            process(compressed[..compressed.len() - 1].to_vec(), true)
                .await
                .is_err()
        );
        let mut trailing = compressed;
        trailing.extend_from_slice(b"junk");
        assert!(process(trailing, true).await.is_err());
    }
}
