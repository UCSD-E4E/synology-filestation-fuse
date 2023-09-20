use super::FileStation;
use std::{time::{SystemTime, Duration}, collections::HashMap};

fn epoch_from_seconds(seconds: u64) -> SystemTime {
	SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

pub struct FileSystemInfo {
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,

    pub is_dir: bool,
    pub size: u64,
	pub ino: u64,
}

pub struct FileStationFileSystem {
    pub filestation: FileStation,
	path2ino: HashMap<String, u64>,
	ino2path: HashMap<u64, String>,
}

impl FileStationFileSystem {
    pub fn new(hostname: &str, port: u16, secured: bool) -> FileStationFileSystem {
		let path2ino = HashMap::new();
		let ino2path = HashMap::new();

        let mut filestation_filesystem = FileStationFileSystem {
            filestation: FileStation::new(hostname, port, secured),
			path2ino,
			ino2path
        };
		filestation_filesystem.insert_ino("/");

		return filestation_filesystem;
    }

	fn insert_ino(&mut self, path: &str) {
		let next_ino = (self.path2ino.len() + 1) as u64;
		self.path2ino.insert(path.to_string(), next_ino);
		self.ino2path.insert(next_ino, path.to_string());
	}

	pub fn get_info_for_ino(&mut self, ino: u64) -> Result<FileSystemInfo, i32> {
		let path = self.ino2path[&ino].clone();
		self.get_info_for_path(&path)
	}
    
    pub fn get_info_for_path(&mut self, file_name: &str) -> Result<FileSystemInfo, i32> {
		let file_name_str = file_name.to_string();

		if file_name_str == "/" {
			let shares = self.filestation.list_shares();

			return match shares {
				Ok(res) => {
					let mut totalspace: u64 = 0;
					let mut atime: u64 = 0;
					let mut ctime: u64 = 0;
					let mut crtime: u64 = 0;
					let mut mtime: u64 = 0;

					for share in res.shares.iter() {
						if totalspace < share.additional.volume_status.totalspace {
							totalspace = share.additional.volume_status.totalspace;

							atime = share.additional.time.atime;
                            ctime = share.additional.time.ctime;
							crtime = share.additional.time.crtime;
							mtime = share.additional.time.mtime;
						}
					}

					Ok(FileSystemInfo {
                        atime: epoch_from_seconds(atime),
                        ctime: epoch_from_seconds(ctime),
                        crtime: epoch_from_seconds(crtime),
                        mtime: epoch_from_seconds(mtime),
						size: 0,
						is_dir: true,
						ino: self.path2ino[&file_name_str]
					})
				},
				Err(error) => {
					return Err(error);
				}
			}
		} else if file_name_str.matches("/").count() == 1 {
			let shares = self.filestation.list_shares();
			return match shares {
				Ok(res) => {
					for share in res.shares.iter() {
						if share.path == file_name_str {
							self.insert_ino(&file_name_str);

							return Ok(FileSystemInfo {
                                atime: epoch_from_seconds(share.additional.time.atime),
                                ctime: epoch_from_seconds(share.additional.time.ctime),
                                crtime: epoch_from_seconds(share.additional.time.crtime),
                                mtime: epoch_from_seconds(share.additional.time.mtime),
								size: 0,
								is_dir: true,
								ino: self.path2ino[&file_name_str]
							});
						}
					}

					return Err(-1);
				},
				Err(error) => Err(error)
			}
		} else {
			let files_result = self.filestation.get_info_for_path(&file_name_str);
			return match files_result {
				Ok(file) => {
					self.insert_ino(&file_name_str);

					let mut size: u64 = 0;
					if !file.isdir {
						size = file.additional.size;
					}

					return Ok(FileSystemInfo {
                        atime: epoch_from_seconds(file.additional.time.atime),
                        ctime: epoch_from_seconds(file.additional.time.ctime),
                        crtime: epoch_from_seconds(file.additional.time.crtime),
                        mtime: epoch_from_seconds(file.additional.time.mtime),
                        size,
                        is_dir: file.isdir,
						ino: self.path2ino[&file_name_str]
					});
				},
				Err(error) => Err(error)
			}
		}
	}

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), i32> {
        self.filestation.login(username, password)
    }
}