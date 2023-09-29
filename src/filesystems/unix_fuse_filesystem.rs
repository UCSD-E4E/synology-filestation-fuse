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

    fn create(&mut self, _req: &fuse::Request, _parent: u64, _name: &OsStr, _mode: u32, _flags: u32, reply: fuse::ReplyCreate) {
        reply.error(ENOSYS);
    }

    fn getattr(&mut self, _req: &fuse::Request, ino: u64, reply: fuse::ReplyAttr) {
        let path_result = self.filestation_filesystem.get_path_for_ino(ino);
        if path_result.is_err() {
            reply.error(ENOSYS);
            return;
        }
        let path: String = path_result.unwrap();

        println!("path: {}", path);

        let info_result = self.filestation_filesystem.get_info(&path);
        let ttl: Timespec = Timespec::new(10, 0);

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

    fn lookup(&mut self, _req: &fuse::Request, parent: u64, name: &OsStr, reply: fuse::ReplyEntry) {
        let parent_path_result = self.filestation_filesystem.get_path_for_ino(parent);
        if parent_path_result.is_err() {
            reply.error(ENOSYS);
            return;
        }
        let parent_path: String = parent_path_result.unwrap();
        
        let mut path = format!("{}/{}", parent_path, name.to_str().unwrap());
        path = path.replace("//", "/");
        println!("lookup path: {}", path);

        let info_result = self.filestation_filesystem.get_info(&path);

        if info_result.is_err() {
            reply.error(info_result.err().unwrap());
            return;
        }

        let info = info_result.unwrap();
        let ttl: Timespec = Timespec::new(5, 0);
        reply.entry(
            &ttl,
            &FileAttr {
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
            },
            0);
    }

    fn open(&mut self, _req: &fuse::Request, _ino: u64, _flags: u32, reply: fuse::ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(&mut self, _req: &fuse::Request, _ino: u64, _fh: u64, _offset: i64, _size: u32, reply: fuse::ReplyData) {
        reply.error(ENOSYS);
    }

    fn readdir(&mut self, _req: &fuse::Request, ino: u64, _fh: u64, offset: i64, mut reply: fuse::ReplyDirectory) {
        let path_result = self.filestation_filesystem.get_path_for_ino(ino);
        if path_result.is_err() {
            reply.error(ENOSYS);
            return;
        }
        let path: String = path_result.unwrap();

        println!("offset: {}", offset);

        let result = self.filestation_filesystem.list_files(&path);
        match result {
            Ok(files) => {
                let mut is_next = false;
                if offset == 0 {
                    is_next = true;
                }

                for file in files.iter() {
                    if !is_next {
                        if offset == (file.ino as i64) {
                            is_next = true;
                        }
                        continue;
                    }

                    let file_type: FileType;
                    if file.is_dir {
                        file_type = FileType::Directory;
                    } else {
                        file_type = FileType::RegularFile;
                    }

                    reply.add(file.ino, file.ino as i64, file_type, file.name.clone());
                    reply.ok();

                    return;
                }
            }
            Err(err) => reply.error(err)
        }
    }

    fn statfs(&mut self, _req: &fuse::Request, _ino: u64, reply: fuse::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
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