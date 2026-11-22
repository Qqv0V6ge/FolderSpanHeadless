//! Device discovery, authenticated channels, and transfers.

pub mod devices;
#[cfg(feature = "pro")]
#[rustfmt::skip]
#[path = "../../pro/src/network/official_signaling.rs"]
pub(crate) mod official_signaling;
pub mod transfer;
pub mod transport;
