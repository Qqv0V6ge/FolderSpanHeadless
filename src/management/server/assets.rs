use crate::management::reply::Reply;
use axum::response::{IntoResponse, Response};
use std::path::{Path, PathBuf};

fn locate(root: &Path, path: &str, private: &[PathBuf]) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    let path = decoded.trim_start_matches('/');
    if path.contains(['\\', '\0']) || path.split('/').any(|s| matches!(s, "." | "..")) {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let mut file = root.join(path);
    if file.is_dir() {
        file = file.join("index.html");
    }
    let file = file.canonicalize().ok()?;
    if !file.starts_with(&root) || !file.is_file() {
        return None;
    }
    let canonical = crate::runtime::config::canonical_path(&file).ok()?;
    if private
        .iter()
        .any(|root| crate::storage::files::within(&canonical, root))
    {
        return None;
    }
    Some(file)
}

pub fn has_web_index(root: &Path, private: &[PathBuf]) -> bool {
    locate(root, "/", private).is_some_and(|file| std::fs::File::open(file).is_ok())
}

pub(super) async fn static_asset(
    root: &Path,
    path: &str,
    head: bool,
    private: &[PathBuf],
) -> Response {
    let not_found = || Reply::error(404, "not_found", "not found").into_response();
    let Some(file) = locate(root, path, private) else {
        return not_found();
    };
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
