use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStationFileSystem;

use std::{ffi::OsStr, time::Duration};
use fuser::{FileType, FileAttr, Filesystem, MountOption};
use libc::{ENOSYS, ENOENT};

struct UnixFileSystemHandler {
    filestation_filesystem: FileStationFileSystem,
    block_size: u32
}

impl UnixFileSystemHandler {
    pub fn new(filestation_filesystem: FileStationFileSystem) -> UnixFileSystemHandler {
        UnixFileSystemHandler {
            filestation_filesystem: filestation_filesystem,
            block_size: 4096
        }
    }

    fn size2blocks(&self, size: u64) -> u64 {
        (size + self.block_size as u64 - 1) / self.block_size as u64
    }
}

impl Filesystem for UnixFileSystemHandler {
    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        reply.ok();
    }

    fn destroy(&mut self) {
        self.filestation_filesystem.logout().unwrap();
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        let path_result = self.filestation_filesystem.get_path_for_ino(ino);
        if path_result.is_err() {
            reply.error(ENOSYS);
            return;
        }
        let path: String = path_result.unwrap();

        println!("path: {}", path);

        let info_result = self.filestation_filesystem.get_info(&path);
        let ttl = Duration::from_secs(10);

        match info_result {
            Ok(info) => {
                reply.attr(&ttl, &FileAttr {
                    ino: info.ino,
                    size: info.size,
                    blksize: self.block_size,
                    blocks: self.size2blocks(info.size),
                    atime: info.atime,
                    mtime: info.mtime,
                    ctime: info.ctime,
                    crtime: info.crtime,
                    kind: FileType::Directory,
                    perm: info.perm,
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

    fn lookup(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &OsStr, reply: fuser::ReplyEntry) {
        let parent_path_result = self.filestation_filesystem.get_path_for_ino(parent);
        if parent_path_result.is_err() {
            reply.error(ENOSYS);
            return;
        }
        let parent_path: String = parent_path_result.unwrap();
        
        let mut path = format!("{}/{}", parent_path, name.to_str().unwrap());
        path = path.replace("//", "/");

        let info_result = self.filestation_filesystem.get_info(&path);

        if info_result.is_err() {
            reply.error(info_result.err().unwrap());
            return;
        }
        let info = info_result.unwrap();

        let file_type: FileType;
        if info.is_dir {
            file_type = FileType::Directory;
        } else {
            file_type = FileType::RegularFile;
        }

        let ttl = Duration::from_secs(10);
        reply.entry(
            &ttl,
            &FileAttr {
                ino: info.ino,
                size: info.size,
                blksize: self.block_size,
                blocks: self.size2blocks(info.size),
                atime: info.atime,
                mtime: info.mtime,
                ctime: info.ctime,
                crtime: info.crtime,
                kind: file_type,
                perm: info.perm,
                nlink: 0,
                uid: 501,
                gid: 20,
                rdev: 0,
                flags: 0,
            },
            0);
    }

    fn open(&mut self, _req: &fuser::Request<'_>, _ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
            &mut self,
            _req: &fuser::Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            mut reply: fuser::ReplyDirectory,
        ) {
            let path_result = self.filestation_filesystem.get_path_for_ino(ino);
            if path_result.is_err() {
                reply.error(ENOSYS);
                return;
            }
            let path: String = path_result.unwrap();
    
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
    
                        let _ = reply.add(file.ino, file.ino as i64, file_type, file.name.clone());
                        reply.ok();
    
                        return;
                    }
    
                    reply.ok();
                }
                Err(err) => reply.error(err)
            }
    }

    fn statfs(&mut self, _req: &fuser::Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
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
        ).unwrap();
        filestation_filesystem.login(username, password).unwrap();

        let options = vec![MountOption::RW, MountOption::FSName("SYNO_FileStation".to_string())];
        fuser::mount2(UnixFileSystemHandler::new(filestation_filesystem), mount_point, &options).unwrap();
    }

    fn unmount(&self) {
    }
}