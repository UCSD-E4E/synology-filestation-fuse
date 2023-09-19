pub use self::fuse_fileystem::FuseFileSystem;
#[cfg(target_family = "windows")]
pub use self::windows_fuse_filesystem::WindowsFuseFileSystem;
#[cfg(target_family = "unix")]
pub use self::unix_fuse_filesystem::UnixFuseFileSystem;

pub mod fuse_fileystem;
#[cfg(target_family = "windows")]
pub mod windows_fuse_filesystem;
#[cfg(target_family = "unix")]
pub mod unix_fuse_filesystem;