use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStationFileSystem;

use std::{time::SystemTime, time::Duration, thread};
use dokan::{
    init,
    shutdown,
    unmount,
	is_name_in_expression,
    FileSystemMounter,
    FileSystemHandler,
	FindData,
    CreateFileInfo,
    MountOptions,
    OperationInfo,
    OperationResult,
    DiskSpaceInfo,
    FileInfo,
    VolumeInfo,
    IO_SECURITY_CONTEXT, MountFlags
};
use widestring::{U16CString, UCString, U16CStr};
use winapi::um::winnt;

#[derive(Debug)]
struct WindowsFileSystemEntry {
	// entry: Entry,
	// alt_stream: RwLock<Option<Arc<RwLock<AltStream>>>>,
	// delete_on_close: bool,
	// mtime_delayed: Mutex<Option<SystemTime>>,
	// atime_delayed: Mutex<Option<SystemTime>>,
	// ctime_enabled: AtomicBool,
	// mtime_enabled: AtomicBool,
	// atime_enabled: AtomicBool,

	attributes: u32,
	creation_time: SystemTime,
	last_access_time: SystemTime,
	last_write_time: SystemTime,
	file_size: u64,
	is_dir: bool,
}

struct WindowsFileSystemHandler {
    filestation_filesystem: FileStationFileSystem,
}

fn epoch_from_seconds(seconds: u64) -> SystemTime {
	SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

impl WindowsFileSystemHandler {
    fn new(filestation_filesystem: FileStationFileSystem) -> WindowsFileSystemHandler {
        WindowsFileSystemHandler {
			filestation_filesystem, 
		}
    }

	fn login(& mut self, username: &str, password: &str) -> Result<(), i32> {
		self.filestation_filesystem.login(username, password)
	}

	fn get_filesystem_entry(&self, file_name: &str) -> Result<WindowsFileSystemEntry, i32> {
		let mut file_name_str = file_name.to_string();

		if file_name_str == "\\" {
			let shares = self.filestation_filesystem.filestation.list_shares();

			return match shares {
				Ok(res) => {
					let mut totalspace: u64 = 0;
					let mut crtime: u64 = 0;
					let mut atime: u64 = 0;
					let mut mtime: u64 = 0;

					for share in res.shares.iter() {
						if totalspace < share.additional.volume_status.totalspace {
							totalspace = share.additional.volume_status.totalspace;

							crtime = share.additional.time.crtime;
							atime = share.additional.time.atime;
							mtime = share.additional.time.mtime;
						}
					}

					let size: u64 = res.shares.len() as u64;

					Ok(WindowsFileSystemEntry {
						attributes: winnt::FILE_ATTRIBUTE_DIRECTORY,
						creation_time: epoch_from_seconds(crtime),
						last_access_time: epoch_from_seconds(atime),
						last_write_time: epoch_from_seconds(mtime),
						file_size: size,
						is_dir: true
					})
				},
				Err(error) => {
					return Err(error);
				}
			}
		} else if file_name_str.to_lowercase().contains("desktop.ini") {
			return Err(winapi::shared::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
		} else if file_name_str == "\\AutoRun.inf" {
			return Err(winapi::shared::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
		} else if file_name_str.matches("\\").count() == 1 {
			let shares = self.filestation_filesystem.filestation.list_shares();
			return match shares {
				Ok(res) => {
					file_name_str = file_name_str.replace("\\", "/");

					for share in res.shares.iter() {
						if share.path == file_name_str {
							return Ok(WindowsFileSystemEntry {
								attributes: winnt::FILE_ATTRIBUTE_DIRECTORY,
								creation_time: epoch_from_seconds(share.additional.time.crtime),
								last_access_time: epoch_from_seconds(share.additional.time.atime),
								last_write_time: epoch_from_seconds(share.additional.time.mtime),
								file_size: 0,
								is_dir: true
							});
						}
					}

					return Err(-1);
				},
				Err(error) => {
					if error == 408 {
						Err(winapi::shared::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
					} else {
						Err(error)
					}
				}
			}
		} else {
			file_name_str = file_name_str.replace("\\", "/");

			let files_result = self.filestation_filesystem.filestation.get_info_for_path(&file_name_str);
			return match files_result {
				Ok(file) => {
					let attributes: u32;
					let mut file_size: u64 = 0;
					if file.isdir {
						attributes = winnt::FILE_ATTRIBUTE_DIRECTORY;
					} else {
						attributes = winnt::FILE_ATTRIBUTE_NORMAL;
						file_size = file.additional.size;
					}

					return Ok(WindowsFileSystemEntry {
							attributes,
							creation_time: epoch_from_seconds(file.additional.time.crtime),
							last_access_time: epoch_from_seconds(file.additional.time.atime),
							last_write_time: epoch_from_seconds(file.additional.time.mtime),
							file_size,
							is_dir: file.isdir
					});
				},
				Err(error) => Err(error)
			}
		}
	}
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for WindowsFileSystemHandler {
    type Context = WindowsFileSystemEntry;

    fn create_file(
		&'h self,
		file_name: &U16CStr,
		security_context: &IO_SECURITY_CONTEXT,
		desired_access: winnt::ACCESS_MASK,
		file_attributes: u32,
		_share_access: u32,
		create_disposition: u32,
		create_options: u32,
		info: &mut OperationInfo<'c, 'h, Self>,
	) -> OperationResult<CreateFileInfo<Self::Context>> {
		let file_name_str = file_name.to_string().unwrap();
		println!("file_name: {}", file_name_str);

		match self.get_filesystem_entry(file_name_str.as_str()) {
			Ok(file_entry) => Ok(CreateFileInfo {
				is_dir: file_entry.is_dir,
				context: file_entry,
				new_file_created: false
			}),
			Err(error) => {
				println!("Error: {}", error);

				Err(error)
			}
		}
    }

	fn find_files_with_pattern(
			&'h self,
			file_name: &U16CStr,
			pattern: &U16CStr,
			mut fill_find_data: impl FnMut(&dokan::FindData) -> dokan::FillDataResult,
			_info: &OperationInfo<'c, 'h, Self>,
			_context: &'c Self::Context,
		) -> OperationResult<()> {
		
		if file_name.to_string().unwrap() == "\\" {
			let shares = self.filestation_filesystem.filestation.list_shares();
			return match shares {
				Ok(res) => {
					for share in res.shares.iter() {
						let name = U16CString::from_str(share.name.as_str()).unwrap();

						if is_name_in_expression(pattern, name, false) {
							let result = fill_find_data(&FindData {
								attributes: winapi::um::winnt::FILE_ATTRIBUTE_DIRECTORY,
								creation_time: epoch_from_seconds(share.additional.time.crtime),
								last_access_time: epoch_from_seconds(share.additional.time.atime),
								last_write_time: epoch_from_seconds(share.additional.time.mtime),
								file_size: 0,
								file_name: U16CString::from_str(share.name.as_str()).unwrap()
							});

							if result.is_err() {
								return Err(-2);
							}
						}
					}

					return Ok(());
				},
				Err(error) => {
					Err(error)
				}
			}
		}
		
		let files = self.filestation_filesystem.filestation.list_files(&file_name.to_string().unwrap().replace("\\", "/"));
		match files {
			Ok(res) => {
				for file in res.files.iter() {
					let name = U16CString::from_str(file.name.as_str()).unwrap();

					let attributes: u32;
					let mut file_size: u64 = 0;
					if file.isdir {
						attributes = winnt::FILE_ATTRIBUTE_DIRECTORY;
					} else {
						attributes = winnt::FILE_ATTRIBUTE_NORMAL;
						file_size = file.additional.size;
					}

					if is_name_in_expression(pattern, name, false) {
						let result = fill_find_data(&FindData {
							attributes,
							creation_time: epoch_from_seconds(file.additional.time.crtime),
							last_access_time: epoch_from_seconds(file.additional.time.atime),
							last_write_time: epoch_from_seconds(file.additional.time.mtime),
							file_size,
							file_name: U16CString::from_str(file.name.as_str()).unwrap()
						});

						if result.is_err() {
							return Err(-3);
						}
					}
				}

				return Ok(());
			},
			Err(error) => {
				if error == 408 {
					return Err(winapi::shared::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)
				}
				
				return Err(error);
			}
		}
	}

    fn get_disk_free_space(
		&'h self,
		_info: &OperationInfo<'c, 'h, Self>,
	) -> OperationResult<DiskSpaceInfo> {
		let shares = self.filestation_filesystem.filestation.list_shares();

		match shares {
			Ok(res) => {
				let mut totalspace: u64 = 0;
				let mut freespace: u64 = 0;

				for share in res.shares.iter() {
					if totalspace < share.additional.volume_status.totalspace {
						totalspace = share.additional.volume_status.totalspace;
						freespace = share.additional.volume_status.freespace;
					}
				}

				Ok(DiskSpaceInfo {
					byte_count: totalspace,
					free_byte_count: freespace,
					available_byte_count: freespace,
				})
			},
			Err(error) => {
				Err(error)
			}
		}
	}

	fn get_file_information(
		&'h self,
		file_name: &U16CStr,
		_info: &OperationInfo<'c, 'h, Self>,
		_context: &'c Self::Context,
	) -> OperationResult<FileInfo> {
		let file_name_str = file_name.to_string().unwrap();

		println!("file_name: {}", file_name_str);

		match self.get_filesystem_entry(file_name_str.as_str()) {
			Ok(file_entry) => Ok(FileInfo {
				attributes: file_entry.attributes,
				creation_time: file_entry.creation_time,
				last_access_time: file_entry.last_access_time,
				last_write_time: file_entry.last_write_time,
				file_size: file_entry.file_size,
				number_of_links: 0,
				file_index: 0
			}),
			Err(error) => Err(error)
		}
	}

    fn get_file_security(
		&'h self,
		_file_name: &U16CStr,
		security_information: u32,
		security_descriptor: winnt::PSECURITY_DESCRIPTOR,
		buffer_length: u32,
		_info: &OperationInfo<'c, 'h, Self>,
		context: &'c Self::Context,
	) -> OperationResult<u32> {
		Ok(0)
	}


    fn get_volume_information(
		&'h self,
		_info: &OperationInfo<'c, 'h, Self>,
	) -> OperationResult<VolumeInfo> {
		Ok(VolumeInfo {
			name: U16CString::from_str(self.filestation_filesystem.filestation.hostname.as_str()).unwrap(),
			serial_number: 0,
			max_component_length: 255,
			fs_flags: winnt::FILE_CASE_PRESERVED_NAMES
				| winnt::FILE_CASE_SENSITIVE_SEARCH
				| winnt::FILE_UNICODE_ON_DISK
				| winnt::FILE_PERSISTENT_ACLS
				| winnt::FILE_NAMED_STREAMS,
			// Custom names don't play well with UAC.
			fs_name: U16CString::from_str("NTFS").unwrap(),
		})
	}

    fn mounted(
		&'h self,
		_mount_point: &U16CStr,
		_info: &OperationInfo<'c, 'h, Self>,
	) -> OperationResult<()> {
        Ok(())
	}

	fn read_file(
			&'h self,
			file_name: &U16CStr,
			offset: i64,
			buffer: &mut [u8],
			info: &OperationInfo<'c, 'h, Self>,
			context: &'c Self::Context,
		) -> OperationResult<u32> {
		let file_name_str = file_name.to_string().unwrap();

		println!("file_name: {}", file_name_str);

		return Ok(0);
	}

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        self.filestation_filesystem.filestation.logout()
	}
}

pub struct WindowsFuseFileSystem {
    hostname: String,
    port: u16,
    secured: bool,
    version: u8,
    mount_point: Option<UCString<u16>>,
	debug: bool,
}

impl FuseFileSystem for WindowsFuseFileSystem {
    fn new(hostname: &str, port: u16, secured: bool, version: u8, debug: bool) -> WindowsFuseFileSystem {
        WindowsFuseFileSystem {
            hostname: hostname.to_string(),
            port,
            secured,
            version,
            mount_point: Default::default(),
			debug
        }
    }

    fn mount(&mut self, mount_point: &str, username: &str, password: &str) {
        init();

        let cstr_mount = U16CString::from_str(mount_point).unwrap();
        self.mount_point = Some(cstr_mount.clone());

        let unc_name = U16CString::from_str(self.hostname.as_str()).unwrap();
        let filestation_filesystem = FileStationFileSystem::new(
            &self.hostname,
            self.port,
            self.secured,
            self.version
        );

		let username_string = username.to_string();
		let password_string = password.to_string();

        let executor = move || {
            let mut handler = WindowsFileSystemHandler::new(filestation_filesystem);
            let options = MountOptions {
                flags: MountFlags::ALT_STREAM | MountFlags::DEBUG | MountFlags::STDERR | MountFlags::NETWORK,
                unc_name: Some(unc_name.as_ref()),
                ..Default::default()
            };

			handler.login(username_string.as_str(), password_string.as_str()).unwrap();
            let mut mounter = FileSystemMounter::new(&handler, &cstr_mount, &options);
            let _ = mounter.mount().unwrap();
        };

		if self.debug {
        	executor();
		} else {
        	thread::spawn(executor);
		}
    }

    fn unmount(&self) {
        // Try to unmount.  Does not really matter as we are closing anyways.
        let _ = unmount(self.mount_point.as_ref().unwrap());
        shutdown();
    }
}