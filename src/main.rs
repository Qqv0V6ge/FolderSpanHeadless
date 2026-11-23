mod host;
mod tui;

use anyhow::{Result, ensure};
use folderspan_headless::config::{DISPLAY_NAME, Launch};
use std::io::{IsTerminal, stdin, stdout};
use tokio_util::sync::CancellationToken;

fn main() -> Result<()> {
    let Some(launch) = Launch::parse(std::env::args().skip(1))? else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    if stdin().is_terminal() {
        ensure!(
            stdout().is_terminal(),
            "the management interface requires terminal output"
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        {
            let _runtime = runtime.enter();
            host::cancel_on_signal(cancel.clone())?;
        }
        tui::run(launch, &runtime, cancel)
    } else {
        host::run(launch, cancel, true, |address| {
            let endpoint = host::local_endpoint(address);
            println!(
                "{DISPLAY_NAME} v{}: http://{endpoint} and https://{endpoint}",
                folderspan_headless::wire::VERSION,
            );
        })
    }
}
