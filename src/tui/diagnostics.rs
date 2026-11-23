use crate::host;
use anyhow::{Result, ensure};
use folderspan_headless::{
    config::{Launch, canonical_path, restrict_private},
    instance_lock::desktop_data_dir,
    server, tls, wire,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Clone, Copy)]
pub(super) enum ResultLevel {
    Ready,
    Notice,
    Error,
}

pub(super) struct Check {
    pub(super) label: &'static str,
    export_label: &'static str,
    pub(super) level: ResultLevel,
    pub(super) summary: &'static str,
    pub(super) detail: String,
}

impl Check {
    fn new(
        label: &'static str,
        export_label: &'static str,
        level: ResultLevel,
        summary: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            label,
            export_label,
            level,
            summary,
            detail: detail.into(),
        }
    }
}

#[derive(Default)]
pub(super) struct Report {
    header: String,
    pub(super) checks: Vec<Check>,
}

impl Report {
    pub(super) fn summary(&self) -> String {
        let mut summary = self.header.clone();
        for check in &self.checks {
            summary.push_str(&format!("\n{}: {}", check.export_label, check.detail));
        }
        summary
    }
}

pub(super) async fn report(
    launch: &Launch,
    own: Option<SocketAddr>,
    owns_service: bool,
    state: &str,
) -> Report {
    use ResultLevel::{Error, Notice, Ready};
    let data = &launch.data_dir;
    let mut report = Report {
        header: format!(
            "FolderSpanHeadless {} diagnostic summary\n{state}\nData directory: {}",
            env!("CARGO_PKG_VERSION"),
            data.display()
        ),
        checks: Vec::new(),
    };
    let (level, summary, detail) = match fs::symlink_metadata(data) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            (Ready, "可用", "directory exists")
        }
        Ok(_) => (Error, "类型无效", "invalid directory type"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (Notice, "尚未创建", "directory has not been created")
        }
        Err(_) => (Error, "无法读取", "directory cannot be inspected"),
    };
    report.checks.push(Check::new(
        "数据目录",
        "Data directory check",
        level,
        summary,
        detail,
    ));

    let (level, summary, detail) = match tls::Identity::certificate_status(data) {
        Ok(Some(status)) if status.valid => (Ready, "有效", status.summary),
        Ok(Some(status)) => (Error, "不在有效期内", status.summary),
        Ok(None) => (
            Notice,
            "尚未生成",
            "certificate has not been generated".into(),
        ),
        Err(error) => (Error, "无法读取", format!("{error}")),
    };
    report.checks.push(Check::new(
        "TLS 证书",
        "TLS certificate",
        level,
        summary,
        detail,
    ));

    let settings = match launch.load_settings() {
        Ok((settings, _)) => launch.resolve(settings).settings,
        Err(error) => {
            report.checks.push(Check::new(
                "部署配置",
                "Deployment settings",
                Error,
                "无法读取",
                format!("{error}"),
            ));
            return report;
        }
    };
    let private = [Some(data.to_owned()), desktop_data_dir().ok()]
        .into_iter()
        .flatten()
        .map(|path| canonical_path(&path).unwrap_or(path))
        .collect::<Vec<_>>();
    let (level, summary, detail) = if server::has_web_index(&settings.web_root, &private) {
        (Ready, "入口可读", "index.html is readable")
    } else {
        (
            Notice,
            "入口不可用",
            "index.html is missing, unreadable or outside the allowed Web directory",
        )
    };
    report.checks.push(Check::new(
        "Web 资源",
        "Web resources",
        level,
        summary,
        format!("{detail} ({})", settings.web_root.display()),
    ));

    let origin = match settings.policy([]) {
        Ok(_) => Check::new("Origin 规则", "Origin policy", Ready, "有效", "valid"),
        Err(error) => Check::new(
            "Origin 规则",
            "Origin policy",
            Error,
            "无效",
            format!("{error}"),
        ),
    };
    report.checks.push(origin);

    let (level, summary, detail) = if let Some(actual) = own {
        (
            Ready,
            "本窗口正在监听",
            format!("this TUI owns the listener at {actual}"),
        )
    } else if owns_service {
        (
            Notice,
            "等待服务启动",
            "waiting for managed service startup".into(),
        )
    } else {
        match host::bind(&settings).await {
            Ok(listener) => {
                drop(listener);
                (Ready, "可绑定", format!("{} can be bound", settings.port))
            }
            Err(error) => (Error, "无法绑定", format!("{error:#}")),
        }
    };
    report
        .checks
        .push(Check::new("监听端口", "Port check", level, summary, detail));
    report.checks.push(endpoint_for(&settings, own).await);
    report
}

pub(super) async fn endpoint(launch: &Launch, own: Option<SocketAddr>) -> Check {
    match launch.load_settings() {
        Ok((settings, _)) => endpoint_for(&launch.resolve(settings).settings, own).await,
        Err(error) => Check::new(
            "管理端点",
            "Endpoint check",
            ResultLevel::Error,
            "配置不可用",
            format!("{error}"),
        ),
    }
}

async fn endpoint_for(
    settings: &folderspan_headless::config::Settings,
    own: Option<SocketAddr>,
) -> Check {
    use ResultLevel::{Notice, Ready};
    let expected = settings
        .bind_address
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let local = expected.is_unspecified()
        || expected.is_loopback()
        || if_addrs::get_if_addrs().is_ok_and(|all| all.iter().any(|item| item.ip() == expected));
    let destination = own.or_else(|| {
        (settings.port != 0 && local).then_some(SocketAddr::new(expected, settings.port))
    });
    let (level, summary, detail) = match destination.map(host::local_endpoint) {
        Some(endpoint) if reachable(endpoint).await => (
            Ready,
            "可连接",
            format!(
                "http://{endpoint} responded with protocol v{}",
                wire::VERSION
            ),
        ),
        Some(endpoint) => (
            Notice,
            "无响应",
            format!("no compatible response from http://{endpoint}"),
        ),
        None => (Notice, "无法探测", "no fixed local address to probe".into()),
    };
    Check::new("管理端点", "Management endpoint", level, summary, detail)
}

async fn reachable(endpoint: SocketAddr) -> bool {
    let probe = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut response = client
            .get(format!("http://{endpoint}/api/web-ui/bootstrap"))
            .send()
            .await?;
        ensure!(response.status().is_success(), "bootstrap failed");
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(bytes.len() + chunk.len() <= 1024, "invalid bootstrap");
            bytes.extend_from_slice(&chunk);
        }
        let info: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok::<_, anyhow::Error>(
            info["mode"] == "attached"
                && info["transport"] == "websocket"
                && info["protocolVersion"] == wire::VERSION,
        )
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(750), probe).await,
        Ok(Ok(true))
    )
}

pub fn export(path: &Path, summary: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = (|| {
        restrict_private(path, false)?;
        writeln!(file, "{summary}")?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
