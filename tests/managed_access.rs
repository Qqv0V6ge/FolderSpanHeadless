use anyhow::Result;
use folderspan_headless::{
    access::{Access, Credentials, DirectoryGrant, Feature},
    config::{Config, Settings, canonical_path},
    server,
    wire::{self, Packet},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn issued_access_is_enforced_on_http_and_websocket() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = canonical_path(dir.path())?;
    let data = root.join("data");
    let share = root.join("share");
    let readonly = share.join("readonly");
    let sibling = root.join("share-other");
    let web = root.join("web");
    for path in [&data, &readonly, &sibling, &web] {
        std::fs::create_dir_all(path)?;
    }
    std::fs::write(readonly.join("letter"), b"read-only")?;
    std::fs::write(sibling.join("letter"), b"private")?;
    std::fs::write(share.join("writable"), b"original")?;
    std::fs::write(web.join("index.html"), b"<main>Ready</main>")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sibling, share.join("alias"))?;

    let mut keys = Credentials::load(&data)?;
    let full = keys.add("Full".into(), Access::Full)?;
    let scoped = keys.add(
        "Scoped".into(),
        Access::Scoped {
            features: BTreeSet::from([Feature::Storage]),
            directories: vec![
                DirectoryGrant {
                    path: share.clone(),
                    write: true,
                },
                DirectoryGrant {
                    path: readonly.clone(),
                    write: false,
                },
            ],
        },
    )?;
    keys.save(&data)?;
    let cfg = Config {
        data_dir: data.clone(),
        settings: Settings {
            web_root: web,
            bind_address: Some("127.0.0.1".parse()?),
            port: 0,
            allowed_origins: String::new(),
        },
    };
    let app = server::App::new(cfg, Credentials::load(&data)?)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let serving = tokio::spawn(server::serve(listener, app, cancel.clone()));
    let base = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build()?;
    let login = |secret: &str| {
        client
            .post(format!("{base}/api/web-ui/login"))
            .json(&json!({"secret":secret,"protocolVersion":wire::VERSION}))
            .send()
    };
    assert_eq!(
        client.get(&base).send().await?.text().await?,
        "<main>Ready</main>"
    );
    let full_session: Value = login(&full).await?.error_for_status()?.json().await?;
    assert!(
        full_session["host"]["roots"]
            .as_array()
            .is_some_and(|roots| !roots.is_empty())
    );
    let session: Value = login(&scoped).await?.error_for_status()?.json().await?;
    let token = session["sessionToken"].as_str().unwrap();
    assert_eq!(session["host"]["roots"][0]["path"], json!(share));
    assert_eq!(session["host"]["roots"][1]["path"], json!(readonly));
    assert_eq!(session["host"]["roots"].as_array().unwrap().len(), 2);
    let query = |path: &Path| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("path", path.to_str().unwrap())
            .finish()
    };
    let body_request = |method: reqwest::Method, path: &Path| {
        client
            .request(
                method,
                format!(
                    "{base}/api/web-ui/platform/files/content?{}&size=3&offset=0",
                    query(path)
                ),
            )
            .header("X-FolderSpan-WebUi-Session", token)
            .header("X-FolderSpan-WebUi-Version", "1")
    };
    assert_eq!(
        body_request(reqwest::Method::GET, &readonly.join("letter"))
            .send()
            .await?
            .text()
            .await?,
        "read-only"
    );
    for path in [readonly.join("letter"), sibling.join("letter")] {
        assert_eq!(
            body_request(reqwest::Method::PUT, &path)
                .body("new")
                .send()
                .await?
                .status(),
            403
        );
    }
    #[cfg(unix)]
    assert_eq!(
        body_request(reqwest::Method::GET, &share.join("alias/letter"))
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        body_request(reqwest::Method::PUT, &share.join("writable"))
            .body("new")
            .send()
            .await?
            .status(),
        200
    );
    assert_eq!(std::fs::read(share.join("writable"))?, b"new");

    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{address}/api/web-ui/socket")).await?;
    let mut auth = Packet::new("auth");
    auth.header.token = token.to_owned();
    ws.send(Message::Binary(auth.encode()?.into())).await?;
    let ready = timeout(std::time::Duration::from_secs(5), ws.next())
        .await?
        .unwrap()?;
    assert_eq!(
        Packet::decode(&ready.into_data())?.header.kind,
        "authenticated"
    );

    let delete = format!("/api/web-ui/platform/files/tree?{}", query(&share));
    let cases = [
        (
            "GET",
            "/api/web-ui/platform/storage/accounts",
            json!(null),
            200,
        ),
        ("GET", "/api/web-ui/platform/files/roots", json!(null), 200),
        (
            "POST",
            "/api/web-ui/platform/files/move",
            json!({"from":share.join("writable"),"to":readonly.join("moved")}),
            403,
        ),
        ("DELETE", delete.as_str(), json!(null), 403),
        (
            "POST",
            "/api/web-ui/platform/listeners",
            json!({"port":12987,"kind":"link-share","callbackId":"test"}),
            403,
        ),
        (
            "POST",
            "/api/web-ui/platform/listeners",
            json!({"port":12987,"kind":"mcp","callbackId":"test"}),
            403,
        ),
        (
            "POST",
            "/api/web-ui/platform/listeners",
            json!({"port":12987,"kind":"device","callbackId":"test"}),
            403,
        ),
        (
            "POST",
            "/api/web-ui/platform/devices/sign",
            json!(null),
            403,
        ),
        (
            "POST",
            "/api/web-ui/platform/http/clients",
            json!(null),
            403,
        ),
    ];
    for (index, (method, path, body, status)) in cases.into_iter().enumerate() {
        let mut request = Packet::new("request");
        request.header.id = index as i64 + 1;
        request.header.path = path.to_owned();
        request.header.method = method.to_owned();
        if !body.is_null() {
            request.body = serde_json::to_vec(&body)?;
        }
        ws.send(Message::Binary(request.encode()?.into())).await?;
        let response = timeout(std::time::Duration::from_secs(5), ws.next())
            .await?
            .unwrap()?;
        let response = Packet::decode(&response.into_data())?;
        assert_eq!(response.header.status, status, "{method} {path}");
    }
    ws.close(None).await?;
    assert_eq!(std::fs::read(readonly.join("letter"))?, b"read-only");
    assert!(!readonly.join("moved").exists());
    cancel.cancel();
    serving.await??;
    Ok(())
}
