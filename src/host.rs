use anyhow::{Context, Result, ensure};
use folderspan_headless::{
    access::Credentials,
    config::{Launch, Settings},
    instance_lock::LockedProfile,
    listeners, server,
};
use std::net::SocketAddr;
use tokio::{net::TcpListener, runtime::Builder};
use tokio_util::sync::CancellationToken;

pub fn run(
    mut launch: Launch,
    cancel: CancellationToken,
    watch_signals: bool,
    ready: impl FnOnce(SocketAddr),
) -> Result<()> {
    let profile = LockedProfile::acquire(&launch.data_dir)?;
    launch.data_dir = profile.data_dir.clone();
    let (settings, _) = launch.load_settings()?;
    let config = launch.resolve(settings);
    let credentials = Credentials::load(&config.data_dir)?;
    ensure!(
        !credentials.keys().is_empty(),
        "Open FolderSpanHeadless in a terminal and create the first Web access key before starting the service."
    );
    // Keep the locks until runtime shutdown has waited for blocking I/O.
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        if watch_signals {
            cancel_on_signal(cancel.clone())?;
        }
        if cancel.is_cancelled() {
            return Ok(());
        }
        let listener = bind(&config.settings).await?;
        let app = server::App::new(config, credentials)?;
        if !cancel.is_cancelled() {
            ready(listener.local_addr()?);
        }
        server::serve(listener, app, cancel).await
    })
}

pub async fn bind(settings: &Settings) -> Result<TcpListener> {
    match settings.bind_address {
        Some(ip) => TcpListener::bind((ip, settings.port))
            .await
            .with_context(|| format!("cannot bind Web UI to {ip}:{}", settings.port)),
        None => listeners::bind_public(settings.port)
            .with_context(|| format!("cannot bind Web UI to port {}", settings.port)),
    }
}

pub fn cancel_on_signal(cancel: CancellationToken) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            cancel.cancel();
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel.cancel();
    });
    Ok(())
}

pub fn local_endpoint(address: SocketAddr) -> SocketAddr {
    if address.ip().is_unspecified() {
        let loopback = if address.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        };
        SocketAddr::new(loopback, address.port())
    } else {
        address
    }
}
