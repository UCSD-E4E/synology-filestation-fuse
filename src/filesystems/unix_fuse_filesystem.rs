use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStationFileSystem;

use std::ffi::OsStr;
use fuse::Filesystem;

struct UnixFileSystemHandler {
    filestation_filesystem: FileStationFileSystem
}

impl UnixFileSystemHandler {
    pub fn new(filestation_filesystem: FileStationFileSystem) -> UnixFileSystemHandler {
        UnixFileSystemHandler {
            filestation_filesystem: filestation_filesystem
        }
    }
}

impl Filesystem for UnixFileSystemHandler {
}

pub struct UnixFuseFileSystem {
    hostname: String,
    port: u16,
    secured: bool,
}

impl FuseFileSystem for UnixFuseFileSystem {
    fn new(hostname: &str, port: u16, secured: bool, _debug: bool) -> UnixFuseFileSystem {
        UnixFuseFileSystem {
            hostname: hostname.to_string(),
            port,
            secured
        }
    }

    fn mount(&mut self, mount_point: &str, username: &str, password: &str) {
        let mut filestation_filesystem = FileStationFileSystem::new(
            &self.hostname,
            self.port,
            self.secured,
        );
        filestation_filesystem.login(username, password).unwrap();

        let options = ["-o", "ro", "-o", "fsname=SYNO_FileStation"]
            .iter()
            .map(|o| o.as_ref())
            .collect::<Vec<&OsStr>>();
        fuse::mount(UnixFileSystemHandler::new(filestation_filesystem), &OsStr::new(mount_point), &options).unwrap();
    }

    fn unmount(&self) {
    }
}