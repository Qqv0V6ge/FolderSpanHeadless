use crate::management::reply::Reply;
use axum::response::{IntoResponse, Response};
use std::path::{Path, PathBuf};

pub(super) async fn static_asset(
    root: &Path,
    path: &str,
    head: bool,
    private: &[PathBuf],
) -> Response {
    let not_found = || Reply::error(404, "not_found", "not found").into_response();
    let Ok(decoded) = percent_encoding::percent_decode_str(path).decode_utf8() else {
        return not_found();
    };
    let path = decoded.trim_start_matches('/');
    if path.contains(['\\', '\0']) || path.split('/').any(|s| matches!(s, "." | "..")) {
        return not_found();
    }
    let Ok(root) = root.canonicalize() else {
        return not_found();
    };
    let mut file = root.join(path);
    if file.is_dir() {
        file = file.join("index.html");
    }
    let Ok(file) = file.canonicalize() else {
        return not_found();
    };
    if !file.starts_with(&root) || !file.is_file() {
        return not_found();
    }
    let Ok(canonical) = crate::runtime::config::canonical_path(&file) else {
        return not_found();
    };
    if private
        .iter()
        .any(|root| crate::storage::files::within(&canonical, root))
    {
        return not_found();
    }
    let Ok(stream) = tokio::fs::File::open(&file).await else {
        return not_found();
    };
    let Ok(metadata) = stream.metadata().await else {
        return not_found();
    };
    let body = if head {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(stream))
    };
    axum::http::Response::builder()
        .status(200)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("content-length", metadata.len())
        .header(
            "content-type",
            mime_guess::from_path(file).first_or_octet_stream().as_ref(),
        )
        .body(body)
        .expect("valid static response")
}
