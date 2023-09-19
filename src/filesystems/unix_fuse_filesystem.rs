use crate::filesystems::FuseFileSystem;

pub struct UnixFuseFileSystem {
}

impl FuseFileSystem for UnixFuseFileSystem {
    fn new(hostname: &str, port: u16, secured: bool, version: u8, debug: bool) -> UnixFuseFileSystem {
        UnixFuseFileSystem {}
    }

    fn mount(&mut self, mount_point: &str, username: &str, password: &str) {
    }

    fn unmount(&self) {
    }
}