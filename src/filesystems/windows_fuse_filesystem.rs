use crate::filesystems::FuseFileSystem;
use crate::synology_api::FileStation;

use std::{time::SystemTime, thread};
use dokan::{
    init,
    shutdown,
    unmount,
    FileSystemMounter,
    FileSystemHandler,
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
use winapi::{
	shared::{ntdef, ntstatus::*},
	um::winnt,
};

#[derive(Debug)]
struct EntryHandle {
	// entry: Entry,
	// alt_stream: RwLock<Option<Arc<RwLock<AltStream>>>>,
	// delete_on_close: bool,
	// mtime_delayed: Mutex<Option<SystemTime>>,
	// atime_delayed: Mutex<Option<SystemTime>>,
	// ctime_enabled: AtomicBool,
	// mtime_enabled: AtomicBool,
	// atime_enabled: AtomicBool,
}

struct WindowsFileSystemHandler {
    filestation: FileStation,
}

impl WindowsFileSystemHandler {
    fn new(mut filestation: FileStation) -> WindowsFileSystemHandler {
        WindowsFileSystemHandler { filestation }
    }

	fn login(& mut self, username: &str, password: &str) {
		self.filestation.login(username, password);
	}
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for WindowsFileSystemHandler {
    type Context = EntryHandle;

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
        Ok(CreateFileInfo { context: EntryHandle {}, is_dir: true, new_file_created: false } )
    }

    fn get_disk_free_space(
		&'h self,
		_info: &OperationInfo<'c, 'h, Self>,
	) -> OperationResult<DiskSpaceInfo> {
		let shares = self.filestation.get_shares();

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
			Err(_error) => {
				Err(_error)
			}
		}
	}

	fn get_file_information(
		&'h self,
		_file_name: &U16CStr,
		_info: &OperationInfo<'c, 'h, Self>,
		context: &'c Self::Context,
	) -> OperationResult<FileInfo> {
        let now = SystemTime::now();

		Ok(FileInfo {
			attributes: 0,
			creation_time: now,
			last_access_time: now,
			last_write_time: now,
			file_size: 5,
			number_of_links: 1,
			file_index: 0,
		})
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
			name: U16CString::from_str(self.filestation.hostname.as_str()).unwrap(),
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

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        self.filestation.logout()
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
        let filestation = FileStation::new(
            self.hostname.clone(),
            self.port,
            self.secured,
            self.version
        );

		let username_string = username.to_string();
		let password_string = password.to_string();

        let executor = move || {
            let mut handler = WindowsFileSystemHandler::new(filestation);
            let options = MountOptions {
                flags: MountFlags::ALT_STREAM | MountFlags::DEBUG | MountFlags::STDERR | MountFlags::NETWORK,
                unc_name: Some(unc_name.as_ref()),
                ..Default::default()
            };

			handler.login(username_string.as_str(), password_string.as_str());
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