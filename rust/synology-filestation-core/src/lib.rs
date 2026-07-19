//! Pure HTTP client for the Synology FileStation API.
//!
//! This crate is intentionally free of any platform-specific filesystem code
//! (FUSE, WebDAV, WinFsp). It is consumed by the `synology-filestation-fuse`
//! binary for the actual mount logic and by `synology-filestation-py` for
//! Python bindings.

pub mod client;
pub mod error;
pub mod types;

pub use client::{SynologyClient, ThrottleConfig};
pub use error::SynoFsError;
pub use types::{SynoAdditional, SynoFileInfo, SynoOwner, SynoPerm, SynoTime};
