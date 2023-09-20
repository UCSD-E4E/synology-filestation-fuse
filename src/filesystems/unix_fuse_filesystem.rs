use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStation;

use std::ffi::OsStr;
use fuse::Filesystem;

struct UnixFileSystemHandler {

}

impl Filesystem for UnixFileSystemHandler {
}

pub struct UnixFuseFileSystem {
}

impl FuseFileSystem for UnixFuseFileSystem {
    fn new(hostname: &str, port: u16, secured: bool, version: u8, debug: bool) -> UnixFuseFileSystem {
        UnixFuseFileSystem {}
    }

    fn mount(&mut self, mount_point: &str, username: &str, password: &str) {
        let options = ["-o", "ro", "-o", "fsname=SYNO_FileStation"]
            .iter()
            .map(|o| o.as_ref())
            .collect::<Vec<&OsStr>>();
        fuse::mount(UnixFileSystemHandler {}, &OsStr::new(mount_point), &options).unwrap();
    }

    fn unmount(&self) {
    }
}