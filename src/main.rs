use anyhow::{Context, Result};
use folderspan_headless::{
    config::{Config, Credentials, DISPLAY_NAME, private_directory},
    instance_lock::{InstanceLock, desktop_data_dir},
    server,
};
use tokio_util::sync::CancellationToken;
fn main() -> Result<()> {
    let Some(mut config) = Config::parse(std::env::args().skip(1))? else {
        return Ok(());
    };
    private_directory(&config.data_dir)?;
    config.data_dir = folderspan_headless::config::canonical_path(&config.data_dir)?;
    let desktop = desktop_data_dir()?;
    std::fs::create_dir_all(&desktop)?;
    let _desktop_lock = InstanceLock::acquire(&desktop.join("instance.lock"))?;
    let _own_lock = InstanceLock::acquire(&config.data_dir.join("instance.lock"))?;
    let (credentials, key) = Credentials::load(&config.data_dir, config.reset_key)?;
    if let Some(key) = key {
        println!("Web UI key (shown once): {key}");
    }
    if config.reset_key {
        return Ok(());
    }

    // Drop the runtime before the instance locks so blocking I/O finishes while the locks are held.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let cancel = CancellationToken::new();
        let signal = cancel.clone();
        #[cfg(unix)]
        {
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::spawn(async move {
                tokio::select! {_=interrupt.recv()=>{},_=term.recv()=>{}}
                signal.cancel();
            });
        }
        #[cfg(not(unix))]
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            signal.cancel();
        });
        let (address, port) = (config.bind_address, config.port);
        let app = server::App::new(config, credentials)?;
        let listener = match address {
            Some(ip) => tokio::net::TcpListener::bind((ip, port))
                .await
                .with_context(|| format!("cannot bind Web UI to {ip}:{port}"))?,
            None => folderspan_headless::listeners::bind_public(port)?,
        };
        let local_address = listener.local_addr()?;
        let authority = match address {
            Some(_) => local_address.to_string(),
            None => format!("localhost:{}", local_address.port()),
        };
        println!(
            "{DISPLAY_NAME} v{}: http://{authority} and https://{authority}",
            folderspan_headless::wire::VERSION,
        );
        server::serve(listener, app, cancel).await
    })
}
