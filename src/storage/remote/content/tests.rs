use super::*;
use std::io::{BufRead, Write};

async fn call(
    input: &Value,
    config: &mut Option<Value>,
    handle: &mut String,
    session: &Arc<Session>,
    store: &Arc<Storage>,
    root: &std::path::Path,
) -> Result<Reply> {
    let op = input["op"].as_str().context("operation required")?;
    if op == "init" {
        *config = Some(input["config"].clone());
        return Ok(Reply::json(true));
    }
    if op == "reset-context" {
        session.release_wait(handle).await;
        let reply = super::handle(
            "POST",
            "/api/web-ui/platform/storage/content/open",
            Vec::new(),
            session,
            store,
            Host {
                cache_root: root.join("stages"),
                files: Arc::new(crate::storage::files::FilePolicy {
                    private: vec![root.to_owned()],
                }),
            },
            true,
        )
        .await?;
        *handle = serde_json::from_slice::<Value>(&reply.body)?["id"]
            .as_str()
            .context("handle required")?
            .to_owned();
        return Ok(Reply::json(true));
    }
    if matches!(
        op,
        "upload-file" | "download-file" | "stat" | "provider-list" | "provider-mutate"
    ) {
        use std::sync::atomic::AtomicU64;
        use tokio::sync::mpsc;
        let config: Config = serde_json::from_value(config.clone().context("config required")?)?;
        let client = Client::create(&config, Some(store), session, "")?;
        let path: Path = serde_json::from_value(input["path"].clone())?;
        if op == "provider-list" {
            return Ok(Reply::json(
                client.list(&path.path, path.reference.as_ref()).await?,
            ));
        }
        if op == "provider-mutate" {
            let destination: Path = serde_json::from_value(input["destination"].clone())?;
            return Ok(Reply::json(
                client
                    .mutate(
                        input["operation"].as_str().context("operation required")?,
                        &path.path,
                        &destination.path,
                        input["directory"].as_bool().unwrap_or(false),
                        path.reference.as_ref(),
                        destination.reference.as_ref(),
                    )
                    .await?,
            ));
        }
        if op == "stat" {
            return Ok(Reply::json(client.stat(&path).await?));
        }
        let size = input["size"].as_i64().context("size required")?;
        ensure!(
            (0..=4 * 1024 * 1024).contains(&size),
            "test fixture too large"
        );
        let cancel = CancellationToken::new();
        if op == "upload-file" {
            let bytes = std::fs::read(input["source"].as_str().context("source required")?)?;
            ensure!(bytes.len() == size as usize, "test source changed");
            let (tx, rx) = mpsc::channel(2);
            let producer = async move {
                for block in bytes.chunks(64 * 1024) {
                    tx.send(block.to_vec()).await.map_err(|_| PlatformFailure)?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let (_, result) = tokio::try_join!(
                producer,
                client.upload(
                    &path.path,
                    size,
                    rx,
                    Arc::new(AtomicU64::new(0)),
                    &cancel,
                    path.reference.as_ref()
                )
            )?;
            return Ok(Reply::json(result));
        }
        let (tx, mut rx) = mpsc::channel(2);
        let producer = async {
            client
                .download(&path.path, size, &tx, &cancel, path.reference.as_ref())
                .await?;
            drop(tx);
            Ok::<_, anyhow::Error>(())
        };
        let consumer = async {
            let mut bytes = Vec::new();
            while let Some(block) = rx.recv().await {
                let (block, _) = block?;
                ensure!(
                    block.len() <= 4 * 1024 * 1024 - bytes.len(),
                    "test download too large"
                );
                bytes.extend(block);
            }
            ensure!(bytes.len() == size as usize, "test download size changed");
            std::fs::write(
                input["destination"]
                    .as_str()
                    .context("destination required")?,
                bytes,
            )?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(producer, consumer)?;
        return Ok(Reply::json(true));
    }
    if [
        "private-write",
        "private-read",
        "private-metadata",
        "private-delete",
    ]
    .contains(&op)
    {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("handle", handle)
            .append_pair("path", input["path"].as_str().context("path required")?)
            .append_pair(
                "taskKey",
                &input
                    .get("taskKey")
                    .cloned()
                    .unwrap_or(json!(17))
                    .to_string(),
            )
            .append_pair(
                "taskReference",
                input["taskReference"]
                    .as_str()
                    .unwrap_or("00000000-0000-4000-8000-000000000017"),
            );
        for key in ["offset", "length", "size"] {
            if let Some(value) = input.get(key) {
                query.append_pair(key, &value.to_string());
            }
        }
        if op == "private-metadata" {
            query.append_pair("metadata", "true");
        }
        let method = match op {
            "private-write" => "PUT",
            "private-delete" => "DELETE",
            _ => "GET",
        };
        let bytes = input["bytes"]
            .as_str()
            .map(|s| STANDARD.decode(s))
            .transpose()?
            .unwrap_or_default();
        let reply = super::handle(
            method,
            &("/api/web-ui/platform/storage/content/private-file?".to_owned() + &query.finish()),
            bytes,
            session,
            store,
            Host {
                cache_root: root.join("stages"),
                files: Arc::new(crate::storage::files::FilePolicy {
                    private: vec![root.to_owned()],
                }),
            },
            true,
        )
        .await?;
        return Ok(if op == "private-read" {
            Reply::json(STANDARD.encode(reply.body))
        } else {
            reply
        });
    }
    let operation = match op {
        "setup" => "setup-password",
        "unlock" => "unlock-password",
        v => v,
    };
    let mut body = input.clone();
    body.as_object_mut()
        .context("object required")?
        .remove("op");
    body["handle"] = json!(handle);
    body["config"] = config.clone().context("config required")?;
    body["taskKey"] = input.get("taskKey").cloned().unwrap_or(json!(17));
    body["taskReference"] = input
        .get("taskReference")
        .cloned()
        .unwrap_or(json!("00000000-0000-4000-8000-000000000017"));
    let path_key = if ["stage-identity", "stage-complete", "prepare", "publish"].contains(&op) {
        "stagedPath"
    } else {
        "target"
    };
    for (from, to) in [
        ("path", path_key),
        ("directory", "isDirectory"),
        ("identity", "expectedIdentity"),
        (
            "destination",
            if op == "publish" {
                "destinationPath"
            } else {
                "destination"
            },
        ),
    ] {
        if let Some(value) = body.as_object_mut().unwrap().remove(from) {
            body[to] = value;
        }
    }
    super::handle(
        "POST",
        &format!("/api/web-ui/platform/storage/content/{operation}"),
        serde_json::to_vec(&body)?,
        session,
        store,
        Host {
            cache_root: root.join("stages"),
            files: Arc::new(crate::storage::files::FilePolicy {
                private: vec![root.to_owned()],
            }),
        },
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "test-only host-context bridge for content location conformance"]
async fn contract_bridge() {
    if std::env::var("FOLDERSPAN_CONTENT_LOCATION_BRIDGE").as_deref() != Ok("1") {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let root = std::env::var_os("FOLDERSPAN_CONTENT_LOCATION_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned());
    crate::runtime::config::private_directory(&root).unwrap();
    let store = Storage::load(&root).unwrap();
    let session = Session::new(&root).unwrap();
    let opened = super::handle(
        "POST",
        "/api/web-ui/platform/storage/content/open",
        Vec::new(),
        &session,
        &store,
        Host {
            cache_root: root.join("stages"),
            files: Arc::new(crate::storage::files::FilePolicy {
                private: vec![root.to_owned()],
            }),
        },
        true,
    )
    .await
    .unwrap();
    let mut handle = serde_json::from_slice::<Value>(&opened.body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut config = None;
    for line in std::io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if input["op"] == "quit" {
            break;
        }
        let response = match call(&input, &mut config, &mut handle, &session, &store, &root).await {
            Ok(reply) => reply,
            Err(error) => {
                eprintln!("{}: {error:#}", input["op"]);
                Reply::from_error(error)
            }
        };
        let value = if response.status == 200 {
            serde_json::from_slice::<Value>(&response.body).unwrap()
        } else {
            let error: Value = serde_json::from_slice(&response.body).unwrap();
            error["code"]
                .as_str()
                .and_then(|v| v.strip_prefix("storage-content:"))
                .map(|v| json!(v))
                .unwrap_or(Value::Null)
        };
        println!("@CLOUD@{}", json!({"status":response.status,"value":value}));
        std::io::stdout().flush().unwrap();
    }
    session.close_wait().await;
    store.finish_cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_blocking_file_work_finishes_before_context_cleanup() {
    let temporary = tempfile::tempdir_in(
        crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
    )
    .unwrap();
    let root = temporary.path();
    let store = Storage::load(root).unwrap();
    let session = Session::new(root).unwrap();
    let opened = open(
        &session,
        &store,
        Host {
            cache_root: root.join("stages"),
            files: Arc::new(crate::storage::files::FilePolicy {
                private: vec![root.to_owned()],
            }),
        },
    )
    .unwrap();
    let handle = serde_json::from_slice::<Value>(&opened.body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let value = session
        .resource_value(&handle)
        .unwrap()
        .downcast::<Handle>()
        .unwrap();
    let (path, work) = {
        let mut state = value.state.clone().lock_owned().await;
        (state.stages.create(17).unwrap(), state.work.clone())
    };
    let (ready, started) = oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let file = std::fs::File::open(&path).unwrap();
    let work = work.lock_owned().await;
    let request = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || {
            let _work = work;
            let file = file;
            ready.send(()).unwrap();
            wait.recv().unwrap();
            drop(file);
        })
        .await
        .unwrap();
    });
    started.await.unwrap();
    request.abort();
    let closing = session.clone();
    let mut cleanup = tokio::spawn(async move { closing.release_wait(&handle).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut cleanup)
            .await
            .is_err()
    );
    assert!(std::path::Path::new(&path).exists());
    resume.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), cleanup)
        .await
        .unwrap()
        .unwrap();
    assert!(!std::path::Path::new(&path).exists());
    session.close_wait().await;
    store.finish_cleanup().await;
}
