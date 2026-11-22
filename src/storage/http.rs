use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::remote::safe_segment,
};
use anyhow::{Result, ensure};
use futures_util::StreamExt;
use reqwest::Response;

#[derive(Debug)]
pub(crate) struct HttpStatus(pub u16);
impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage HTTP status {}", self.0)
    }
}
impl std::error::Error for HttpStatus {}
pub(crate) fn success(response: Response) -> Result<Response> {
    if !response.status().is_success() {
        return Err(
            anyhow::Error::new(HttpStatus(response.status().as_u16())).context(PlatformFailure)
        );
    }
    Ok(response)
}
pub(crate) fn checked_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && path.encode_utf16().count() <= 16 * 1024
            && !path.chars().any(char::is_control),
        "invalid cloud path"
    );
    let normalized = path.replace('\\', "/");
    ensure!(
        normalized.trim_matches('/').is_empty()
            || normalized.trim_matches('/').split('/').all(safe_segment),
        "invalid cloud path"
    );
    Ok(())
}
pub(crate) async fn text(response: Response) -> Result<String> {
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(part) = stream.next().await {
        let part = part.map_err(|_| PlatformFailure)?;
        ensure!(
            part.len() <= 8 * 1024 * 1024 - bytes.len(),
            ResourceUnavailable("storage response exceeds limit")
        );
        bytes.extend_from_slice(&part);
    }
    String::from_utf8(bytes).map_err(|_| ResourceUnavailable("invalid storage response").into())
}

pub(crate) async fn read_file(
    client: &reqwest::Client,
    target: url::Url,
    size: i64,
    headers: reqwest::header::HeaderMap,
    output: &tokio::sync::mpsc::Sender<crate::storage::remote::DownloadPart>,
) -> Result<()> {
    use anyhow::Context;
    use std::collections::HashSet;
    let mut current = target.clone();
    let mut seen = HashSet::new();
    for _ in 0..6 {
        ensure!(
            seen.insert(current.to_string()),
            ResourceUnavailable("Storage redirect cycle")
        );
        let response = client
            .get(current.clone())
            .headers(headers.clone())
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        if [301, 302, 303, 307, 308].contains(&response.status().as_u16()) {
            let next = current.join(
                response
                    .headers()
                    .get("location")
                    .context(ResourceUnavailable("Storage redirect has no destination"))?
                    .to_str()?,
            )?;
            ensure!(
                next.origin() == target.origin()
                    && next.username().is_empty()
                    && next.password().is_none_or(str::is_empty),
                ResourceUnavailable("Storage redirect leaves the allowed origin or root")
            );
            current = next;
            continue;
        }
        let mut delivered = false;
        return stream_file(response, size, output, &mut delivered).await;
    }
    Err(ResourceUnavailable("Too many storage redirects").into())
}

pub(crate) async fn stream_file(
    response: Response,
    size: i64,
    output: &tokio::sync::mpsc::Sender<crate::storage::remote::DownloadPart>,
    delivered: &mut bool,
) -> Result<()> {
    use anyhow::Context;
    if !response.status().is_success() {
        return Err(anyhow::Error::new(HttpStatus(response.status().as_u16()))
            .context(ResourceUnavailable("Storage download failed")));
    }
    let expected = response
        .content_length()
        .map(i64::try_from)
        .transpose()?
        .unwrap_or(if size >= 0 { size } else { -1 });
    ensure!(
        size < 0 || expected < 0 || size == expected,
        ResourceUnavailable("Storage file size changed")
    );
    let mut received = 0i64;
    let mut body = response.bytes_stream();
    while let Some(part) = body.next().await {
        let part = part.context(PlatformFailure)?;
        for bytes in part.chunks(65536) {
            ensure!(
                expected < 0 || bytes.len() as i64 <= expected - received,
                ResourceUnavailable("Storage download length exceeded")
            );
            output
                .send(Ok((bytes.to_vec(), expected)))
                .await
                .context(PlatformFailure)?;
            *delivered = true;
            received = received
                .checked_add(bytes.len() as i64)
                .context(PlatformFailure)?;
        }
    }
    ensure!(
        expected < 0 || received == expected,
        ResourceUnavailable("Storage download ended early")
    );
    if received == 0 {
        output
            .send(Ok((vec![], 0)))
            .await
            .context(PlatformFailure)?;
    }

    Ok(())
}

pub(crate) async fn body(response: Response, limit: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        ResourceUnavailable("storage response exceeds limit")
    );
    let mut stream = response.bytes_stream();
    let mut data = zeroize::Zeroizing::new(Vec::new());
    while let Some(part) = stream.next().await {
        let part = part.map_err(|_| PlatformFailure)?;
        ensure!(
            part.len() <= limit - data.len(),
            ResourceUnavailable("storage response exceeds limit")
        );
        data.extend_from_slice(&part);
    }
    Ok(data)
}
