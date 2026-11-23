use super::{App, Connection, assets::static_asset, websocket::socket};
use crate::management::{reply::Reply, wire};
use anyhow::Result;
use axum::{
    Router,
    body::to_bytes,
    extract::{Extension, Request, State, WebSocketUpgrade},
    http::{HeaderMap, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::sync::Arc;

#[derive(serde::Deserialize)]
struct LoginRequest {
    #[serde(default)]
    secret: zeroize::Zeroizing<String>,
    #[serde(default, rename = "protocolVersion")]
    protocol_version: i32,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/web-ui/socket", get(socket_upgrade))
        .fallback(http)
        .with_state(app)
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    if headers.get_all(name).iter().count() != 1 {
        return None;
    }
    headers.get(name)?.to_str().ok()
}
fn allows_credentials(connection: &Connection, headers: &HeaderMap) -> bool {
    if connection.scheme == "https" {
        return true;
    }
    if connection.scheme != "http" {
        return false;
    }
    let host = header(headers, "host").and_then(|h| h.parse::<axum::http::uri::Authority>().ok());
    let local_host = host.is_some_and(|h| {
        matches!(
            h.host()
                .trim_matches(['[', ']'])
                .to_ascii_lowercase()
                .as_str(),
            "localhost" | "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1"
        )
    });
    let local_peer = match connection.remote {
        std::net::IpAddr::V4(ip) => ip == std::net::Ipv4Addr::LOCALHOST,
        std::net::IpAddr::V6(ip) => {
            ip == std::net::Ipv6Addr::LOCALHOST
                || ip.to_ipv4_mapped() == Some(std::net::Ipv4Addr::LOCALHOST)
        }
    };
    local_host && local_peer
}
async fn socket_upgrade(
    State(app): State<Arc<App>>,
    Extension(c): Extension<Connection>,
    uri: Uri,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    if uri != "/api/web-ui/socket"
        || !app.policy.allows(&headers, c.scheme, true)
        || header(&headers, "content-length").is_some_and(|s| s != "0")
    {
        return Reply::error(403, "forbidden", "request host or origin is not allowed")
            .into_response();
    }
    let Ok(permit) = app.socket_slots.clone().try_acquire_owned() else {
        return Reply::error(429, "capacity", "management connection capacity reached")
            .into_response();
    };
    match ws {
        Ok(ws) => ws
            .max_message_size(wire::WIRE_LIMIT)
            .max_frame_size(wire::WIRE_LIMIT)
            .write_buffer_size(0)
            .max_write_buffer_size(wire::WIRE_LIMIT * 2)
            .on_upgrade(move |ws| async move {
                let _permit = permit;
                socket(app, ws, allows_credentials(&c, &headers)).await
            }),
        Err(_) => Reply::error(403, "forbidden", "invalid WebSocket upgrade").into_response(),
    }
}
async fn http(
    State(app): State<Arc<App>>,
    Extension(c): Extension<Connection>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let management = path.starts_with("/api/web-ui/");
    if !app.policy.allows(&parts.headers, c.scheme, management) {
        return Reply::error(403, "forbidden", "request host or origin is not allowed")
            .into_response();
    }
    let method = parts.method.as_str();
    let result = if method == "OPTIONS" && management {
        let methods = ["GET", "POST", "PUT", "DELETE"];
        let allowed = [
            "content-type",
            "x-folderspan-webui-session",
            "x-folderspan-webui-version",
            "range",
        ];
        let requested = header(&parts.headers, "access-control-request-headers").unwrap_or("");
        if header(&parts.headers, "origin").is_none()
            || !header(&parts.headers, "access-control-request-method")
                .is_some_and(|v| methods.contains(&v))
            || parts
                .headers
                .get_all("access-control-request-headers")
                .iter()
                .count()
                > 1
            || requested
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .any(|s| !allowed.contains(&s.to_ascii_lowercase().as_str()))
        {
            Reply::error(
                403,
                "forbidden",
                "preflight method or headers are not allowed",
            )
        } else {
            let mut r = Reply::bytes(vec![]);
            r.status = 204;
            r.headers
                .insert("access-control-allow-methods".into(), methods.join(", "));
            r.headers
                .insert("access-control-allow-headers".into(), allowed.join(", "));
            r
        }
    } else if method == "GET" && path == "/api/web-ui/bootstrap" {
        Reply::json(
            json!({"mode":"attached","protocolVersion":wire::VERSION,"transport":"websocket"}),
        )
    } else if method == "POST" && path == "/api/web-ui/login" {
        match to_bytes(body, 16 * 1024)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<LoginRequest>(&b).ok())
        {
            None => Reply::error(400, "invalid_argument", "invalid platform request"),
            Some(v) if v.protocol_version != wire::VERSION as i32 => Reply::error(
                426,
                "incompatible_protocol",
                "update Web and Runtime together",
            ),
            Some(v) => match app.credentials.authorize(&v.secret) {
                None => Reply::error(401, "unauthorized", "authentication failed"),
                Some(access) => match app.create_session(access) {
                    Ok(s) => Reply::json(
                        json!({"ok":true,"sessionToken":s.token,"host":app.host_info(&s)}),
                    ),
                    Err(_) => Reply::error(429, "capacity", "session capacity reached"),
                },
            },
        }
    } else if matches!(path, "/api/web-ui/session" | "/api/web-ui/files") {
        Reply::error(
            426,
            "incompatible_protocol",
            "WebSocket platform protocol v1 is required; update Web and Runtime together",
        )
    } else if management {
        if let Some(session) = header(&parts.headers, "x-folderspan-webui-session")
            .and_then(|t| app.session(t, path != "/api/web-ui/events"))
        {
            if header(&parts.headers, "x-folderspan-webui-version") != Some("1") {
                Reply::error(
                    426,
                    "incompatible_protocol",
                    "update Web and Runtime together",
                )
            } else if method == "POST" && path == "/api/web-ui/logout" {
                app.release(&session.token);
                Reply::json(true)
            } else if path == "/api/web-ui/events"
                || !wire::is_body_route(method, &parts.uri.to_string())
            {
                Reply::error(
                    426,
                    "incompatible_protocol",
                    "WebSocket platform command required",
                )
            } else {
                match to_bytes(body, wire::BODY_LIMIT).await {
                    Ok(body) => {
                        app.operation(
                            method,
                            &parts.uri.to_string(),
                            body.to_vec(),
                            session,
                            allows_credentials(&c, &parts.headers),
                        )
                        .await
                    }
                    Err(_) => Reply::error(400, "invalid_argument", "invalid platform request"),
                }
            }
        } else {
            Reply::error(401, "unauthorized", "session expired")
        }
    } else if matches!(method, "GET" | "HEAD") {
        return static_asset(
            &app.config.settings.web_root,
            path,
            method == "HEAD",
            &app.files.private,
        )
        .await;
    } else {
        Reply::error(404, "not_found", "not found")
    };
    let mut r = result.into_response();
    if management {
        if let Some(origin) = parts.headers.get("origin") {
            r.headers_mut()
                .insert("access-control-allow-origin", origin.clone());
            r.headers_mut().insert("vary", "Origin".parse().unwrap());
            r.headers_mut().insert(
                "access-control-expose-headers",
                "Content-Range, Accept-Ranges, Content-Length, X-FolderSpan-End, X-FolderSpan-Size, X-FolderSpan-Device-Feedback-Timing, X-FolderSpan-Host-Time"
                    .parse()
                    .unwrap(),
            );
        }
    }
    r
}

#[cfg(test)]
mod content_origin_tests {
    use super::*;
    #[test]
    fn content_passwords_require_real_tls_or_exact_local_host_and_peer() {
        fn allowed(scheme: &'static str, host: &str, peer: &str) -> bool {
            let mut headers = HeaderMap::new();
            headers.insert("host", host.parse().unwrap());
            // Forwarding claims do not alter the listener's transport evidence.
            headers.insert("x-forwarded-proto", "https".parse().unwrap());
            headers.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
            allows_credentials(
                &Connection {
                    scheme,
                    remote: peer.parse().unwrap(),
                },
                &headers,
            )
        }
        for host in [
            "localhost:12043",
            "LOCALHOST:12043",
            "127.0.0.1:12043",
            "[::1]:12043",
            "[0:0:0:0:0:0:0:1]:12043",
        ] {
            for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
                assert!(allowed("http", host, peer));
            }
            for peer in ["192.0.2.1", "127.0.0.2", "::ffff:127.0.0.2"] {
                assert!(!allowed("http", host, peer));
            }
        }
        for host in [
            "example.test",
            "127.0.0.2",
            "localhost.example.test",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(!allowed("http", host, "127.0.0.1"));
            assert!(allowed("https", host, "192.0.2.1"));
        }
        assert!(!allowed("ws", "localhost", "127.0.0.1"));
        let connection = Connection {
            scheme: "http",
            remote: "127.0.0.1".parse().unwrap(),
        };
        let mut headers = HeaderMap::new();
        assert!(!allows_credentials(&connection, &headers));
        headers.append("host", "localhost".parse().unwrap());
        headers.append("host", "localhost".parse().unwrap());
        assert!(!allows_credentials(&connection, &headers));
    }
}
