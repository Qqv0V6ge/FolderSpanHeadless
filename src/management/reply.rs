#[derive(Debug)]
pub struct PlatformFailure;
impl std::fmt::Display for PlatformFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("platform operation failed")
    }
}
impl std::error::Error for PlatformFailure {}
#[derive(Debug)]
pub struct ResourceUnavailable(pub &'static str);
impl std::fmt::Display for ResourceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ResourceUnavailable {}
use std::collections::BTreeMap;
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
impl Reply {
    pub fn json(value: impl serde::Serialize) -> Self {
        Self {
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: serde_json::to_vec(&value).expect("serializable response"),
        }
    }
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        let mut r = Self::json(serde_json::json!({"code":code,"error":message}));
        r.status = status;
        r
    }
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "application/octet-stream".into())]),
            body: bytes,
        }
    }
    pub fn from_error(e: anyhow::Error) -> Self {
        if let Some(error) = e.downcast_ref::<crate::storage::content_crypto::ContentError>() {
            return Self::error(400, &format!("storage-content:{:?}", error.0), error.1);
        }

        if e.is::<PlatformFailure>() {
            return Self::error(500, "platform_error", "platform operation failed");
        }
        if let Some(error) = e.downcast_ref::<ResourceUnavailable>() {
            return Self::error(409, "resource_unavailable", error.0);
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            return match io.kind() {
                NotFound => Self::error(404, "not_found", "platform operation failed"),
                PermissionDenied => Self::error(403, "permission_denied", "path access denied"),
                AlreadyExists => Self::error(409, "conflict", "path already exists"),
                _ => Self::error(500, "io_error", "platform operation failed"),
            };
        }
        Self::error(400, "invalid_argument", "invalid platform request")
    }
}
impl axum::response::IntoResponse for Reply {
    fn into_response(self) -> axum::response::Response {
        let mut r = axum::http::Response::builder()
            .status(self.status)
            .header("Cache-Control", "no-store")
            .header("X-Content-Type-Options", "nosniff");
        for (k, v) in self.headers {
            r = r.header(k, v);
        }
        r.body(axum::body::Body::from(self.body))
            .expect("valid response")
    }
}
