//! Native host for the FolderSpan Web UI.

mod management;
mod network;
mod runtime;
mod storage;

pub use management::{compression, reply, security, server, session, wire};
pub use network::{
    listeners, outbound_http,
    peer::{devices, transfer as device_transfer, transport},
    tls, tls_client,
};
pub use runtime::{config, instance_lock};
pub use storage::{
    accounts as storage_accounts, archive, content_crypto, content_history, files,
    remote::{ftp, http_directory, nextcloud, nfs, s3, seafile, sftp, smb, webdav},
};

#[cfg(feature = "pro")]
pub use storage::remote::cloud;

pub mod networks {
    pub use crate::storage::remote::{DownloadPart, Entry, handle};
}

#[cfg(test)]
#[path = "../tests/support/ftp_peer.rs"]
pub(crate) mod ftp_test_peer;
