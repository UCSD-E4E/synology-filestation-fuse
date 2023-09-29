use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStationFileSystem;

use std::{ffi::OsStr, time::{SystemTime, UNIX_EPOCH}};
use time::Timespec;
use fuse::{FileType, FileAttr, Filesystem};
use libc::{ENOSYS, ENOENT};

fn systemtime2timespec(system_time: SystemTime) -> Timespec {
    Timespec { sec: system_time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64, nsec: 0 }
}

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
    fn access(&mut self, _req: &fuse::Request, _ino: u64, _mask: u32, reply: fuse::ReplyEmpty) {
        reply.ok();
    }

    fn getattr(&mut self, _req: &fuse::Request, ino: u64, reply: fuse::ReplyAttr) {
        let info_result = self.filestation_filesystem.get_info_for_ino(ino);
        let ttl: Timespec = Timespec::new(1, 0);

        match info_result {
            Ok(info) => {
                reply.attr(&ttl, &FileAttr {
                    ino: info.ino,
                    size: info.size,
                    blocks: info.size,
                    atime: systemtime2timespec(info.atime),
                    mtime: systemtime2timespec(info.mtime),
                    ctime: systemtime2timespec(info.ctime),
                    crtime: systemtime2timespec(info.crtime),
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 0,
                    uid: 501,
                    gid: 20,
                    rdev: 0,
                    flags: 0,
                })
            },
            Err(_error) => reply.error(ENOENT)
        }
    }

    fn lookup(&mut self, _req: &fuse::Request, _parent: u64, _name: &OsStr, reply: fuse::ReplyEntry) {
        reply.error(ENOSYS);        
    }

    fn open(&mut self, _req: &fuse::Request, _ino: u64, _flags: u32, reply: fuse::ReplyOpen) {
        reply.error(ENOSYS);
    }

    fn readdir(&mut self, _req: &fuse::Request, _ino: u64, _fh: u64, _offset: i64, reply: fuse::ReplyDirectory) {
        reply.error(ENOSYS);
    }
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