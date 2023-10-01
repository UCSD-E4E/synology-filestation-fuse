use super::{FileStation, FileCache, epoch_from_seconds};
use std::{time::{SystemTime, Duration}, collections::HashMap, sync::Mutex, io::{Error, Write}, fs::File};
use log::error;

pub struct FileSystemInfo {
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    pub crtime: SystemTime,

	pub perm: u16,

	pub name: String,
	pub path: String,
    pub is_dir: bool,
    pub size: u64,
	pub ino: u64,
}

pub struct FileStationFileSystem {
    pub filestation: FileStation,

	path2ino: Mutex<HashMap<String, u64>>,
	ino2path: Mutex<HashMap<u64, String>>,
	file_cache: Mutex<FileCache>,
}

impl FileStationFileSystem {
    pub fn new(hostname: &str, port: u16, secured: bool) -> Result<FileStationFileSystem, i32> {
		match FileCache::new(hostname) {
			Ok(filecache) => {
				let path2ino = HashMap::new();
				let ino2path = HashMap::new();

				let filestation_filesystem = FileStationFileSystem {
					filestation: FileStation::new(hostname, port, secured, Duration::from_secs(5)),
					path2ino: Mutex::new(path2ino),
					ino2path: Mutex::new(ino2path),
					file_cache: Mutex::new(filecache)
				};
				filestation_filesystem.insert_ino("/");
				
				Ok(filestation_filesystem)
			},
			Err(err) => Err(err)
		}
    }

	fn insert_ino(&self, path: &str) -> u64 {
		let mut path2ino = self.path2ino.lock().unwrap();
		let mut ino2path = self.ino2path.lock().unwrap();

		let mut path_str = path.to_string();
		path_str = path_str.replace("//", "/");
		if path_str.len() > 1 && path_str.ends_with("/") {
			path_str = path_str.chars().take(path.len() - 1).skip(1).collect();
		}

		let ino: u64;
		if !path2ino.contains_key(&path_str) {
			ino = (path2ino.len() + 1) as u64;
			path2ino.insert(path_str.clone(), ino);
			ino2path.insert(ino, path_str);
		} else {
			ino = path2ino[&path_str];
		}

		drop(path2ino);
		drop(ino2path);

		return ino;
	}

	#[cfg(target_family = "unix")]
	pub fn get_path_for_ino(&self, ino: u64) -> Result<String, i32> {
		let ino2path = self.ino2path.lock();

		match ino2path {
			Ok(map) => {
				let path = map[&ino].clone();
				drop(map);
				Ok(path)
			},
			Err(_error) => Err(-1)
		}
	}
    
    pub fn get_info(&self, file_name: &str) -> Result<FileSystemInfo, i32> {
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
					let ino = path2ino[&file_name_str];

					Ok(FileSystemInfo {
                        atime: epoch_from_seconds(atime),
                        ctime: epoch_from_seconds(ctime),
                        crtime: epoch_from_seconds(crtime),
                        mtime: epoch_from_seconds(mtime),
						ino,
						perm: 0o755,
						name: file_name_str.clone(),
						path: file_name_str,
						size: 0,
						is_dir: true,
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
								name: share.name.clone(),
								path: share.path.clone(),
								size: 0,
								perm: share.additional.perm.posix,
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
						name: file.name,
						path: file.path,
                        size,
						perm: file.additional.perm.posix,
                        is_dir: file.isdir,
						ino
					});
				},
				Err(error) => Err(error)
			}
		}
	}

	pub fn list_files(&self, path: &str) -> Result<Vec<FileSystemInfo>, i32> {
		if path == "/" {
			let shares = self.filestation.list_shares();
			return match shares {
				Ok(res) => {
					let mut found_files: Vec<FileSystemInfo> = Vec::new();

					for share in res.shares.iter() {
						let ino = self.insert_ino(&share.path);

						found_files.push(FileSystemInfo {
							atime: epoch_from_seconds(share.additional.time.atime),
							crtime: epoch_from_seconds(share.additional.time.crtime),
							ctime: epoch_from_seconds(share.additional.time.ctime),
							mtime: epoch_from_seconds(share.additional.time.mtime),
							name: share.name.clone(),
							path: share.path.clone(),
							size: 0,
							ino,
							perm: share.additional.perm.posix,
							is_dir: true
						});
					}

					return Ok(found_files);
				},
				Err(error) => {
					Err(error)
				}
			}
		}
		
		let files = self.filestation.list_files(path);
		match files {
			Ok(res) => {
				let mut found_files: Vec<FileSystemInfo> = Vec::new();

				for file in res.files.iter() {
					let ino = self.insert_ino(&file.path);

					let mut file_size: u64 = 0;
					if !file.isdir {
						file_size = file.additional.size;
					}

					found_files.push(FileSystemInfo {
						atime: epoch_from_seconds(file.additional.time.atime),
						crtime: epoch_from_seconds(file.additional.time.crtime),
						ctime: epoch_from_seconds(file.additional.time.ctime),
						mtime: epoch_from_seconds(file.additional.time.mtime),
						name: file.name.clone(),
						path: file.path.clone(),
						size: file_size,
						perm: file.additional.perm.posix,
						ino,
						is_dir: file.isdir
					});
				}

				return Ok(found_files);
			},
			Err(error) => Err(error)
		}
	}

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), i32> {
        self.filestation.login(username, password)
    }

	pub fn logout(&self) -> Result<(), i32> {
		self.filestation.logout()
	}

	pub fn read_bytes(&self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<u64, i32> {
		let cache = self.file_cache.lock().unwrap();
		match self.get_info(path) {
			Ok(info) => {
				if !cache.is_file_cached(&info) {
					let file_result = cache.create_file_cache(&info);

					if file_result.is_err() {
						return Err(file_result.err().unwrap());
					}

					let mut large_buffer: Vec<u8> = Vec::new();
					let result = self.filestation.download(path, &mut large_buffer);

					if result.is_err() {
						return Err(result.err().unwrap());
					}

					let mut file = file_result.unwrap();

					let write_result = file.write_all(&large_buffer);
					if write_result.is_err() {
						return Err(-1);
					}

					drop(file);
				}

				match cache.get_file_cache(&info) {
					Some(file) => {
						match self.read_from_file(&file, offset, buffer) {
							Ok(size) => Ok(size as u64),
							Err(error) => {
								error!("An error occurred: {}", error);

								Err(-1)
							}
						}
					},
					None => Err(-1)
				}
			},
			Err(error) => Err(error)
		}
	}
	
	#[cfg(target_family = "unix")]
	fn read_from_file(&self, file: &File, offset: u64, buffer: &mut [u8]) -> Result<usize, Error> {
    use std::os::unix::prelude::FileExt;

		file.read_at(buffer, offset)
	}

	#[cfg(target_family = "windows")]
	fn read_from_file(&self, file: &File, offset: u64, buffer: &mut [u8]) -> Result<usize, Error> {
    use std::os::windows::prelude::FileExt;

		file.seek_read(buffer, offset)
	}
}