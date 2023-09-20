use super::FileStation;
use std::{time::{SystemTime, Duration}, collections::HashMap, sync::Mutex};

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
	path2ino: Mutex<HashMap<String, u64>>,
	ino2path: Mutex<HashMap<u64, String>>,
}

impl FileStationFileSystem {
    pub fn new(hostname: &str, port: u16, secured: bool) -> FileStationFileSystem {
		let path2ino = HashMap::new();
		let ino2path = HashMap::new();

        let filestation_filesystem = FileStationFileSystem {
            filestation: FileStation::new(hostname, port, secured),
			path2ino: Mutex::new(path2ino),
			ino2path: Mutex::new(ino2path)
        };
		filestation_filesystem.insert_ino("/");

		return filestation_filesystem;
    }

	fn insert_ino(&self, path: &str) -> u64 {
		let mut path2ino = self.path2ino.lock().unwrap();
		let mut ino2path = self.ino2path.lock().unwrap();

		let mut ino: u64;
		if !path2ino.contains_key(path) {
			ino = (path2ino.len() + 1) as u64;
			path2ino.insert(path.to_string(), ino);
			ino2path.insert(ino, path.to_string());
		} else {
			ino = path2ino[path];
		}

		drop(path2ino);
		drop(ino2path);

		return ino;
	}

	pub fn get_info_for_ino(&self, ino: u64) -> Result<FileSystemInfo, i32> {
		let ino2path = self.ino2path.lock().unwrap();
		let path = ino2path[&ino].clone();
		drop(ino2path);

		self.get_info_for_path(&path)
	}
    
    pub fn get_info_for_path(&self, file_name: &str) -> Result<FileSystemInfo, i32> {
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

					let path2ino = self.path2ino.lock().unwrap();
					Ok(FileSystemInfo {
                        atime: epoch_from_seconds(atime),
                        ctime: epoch_from_seconds(ctime),
                        crtime: epoch_from_seconds(crtime),
                        mtime: epoch_from_seconds(mtime),
						size: 0,
						is_dir: true,
						ino: path2ino[&file_name_str]
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
							let ino = self.insert_ino(&file_name_str);

							return Ok(FileSystemInfo {
                                atime: epoch_from_seconds(share.additional.time.atime),
                                ctime: epoch_from_seconds(share.additional.time.ctime),
                                crtime: epoch_from_seconds(share.additional.time.crtime),
                                mtime: epoch_from_seconds(share.additional.time.mtime),
								size: 0,
								is_dir: true,
								ino
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
					let ino = self.insert_ino(&file_name_str);

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
						ino
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