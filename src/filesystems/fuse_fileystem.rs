use dokan::{FileSystem, FileSystemHandler};

pub trait FuseFileSystem {
    fn new(hostname: &str, port: u16, secured: bool, version: u8) -> Self;
    fn mount(&mut self, mount_point: &str, username: &str, password: &str);
    fn unmount(&self);
}