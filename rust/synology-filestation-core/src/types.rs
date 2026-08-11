use serde::Deserialize;

/// One file or directory returned by SYNO.FileStation.List.
/// When `get_info` is called on a path with no permission or that doesn't exist,
/// the API returns `success:true` but puts `{"code":NNN,"path":"..."}` in the files
/// array instead of a real entry.  The `code` field captures that per-entry error.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SynoFileInfo {
    #[serde(default)]
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub isdir: bool,
    pub additional: Option<SynoAdditional>,
    /// Per-entry error code returned by the API when the entry is inaccessible.
    pub code: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SynoAdditional {
    pub size: Option<u64>,
    pub owner: Option<SynoOwner>,
    pub time: Option<SynoTime>,
    pub perm: Option<SynoPerm>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SynoOwner {
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SynoTime {
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SynoPerm {
    pub posix: u32,
}

/// Generic API response envelope
#[derive(Debug, Deserialize)]
pub struct SynoResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<SynoApiError>,
}

#[derive(Debug, Deserialize)]
pub struct SynoApiError {
    pub code: u32,
}

/// Auth login response
#[derive(Debug, Deserialize)]
pub struct AuthData {
    pub sid: String,
}

/// List response data
#[derive(Debug, Deserialize)]
pub struct ListData {
    pub files: Vec<SynoFileInfo>,
}

/// ListShare response data
#[derive(Debug, Deserialize)]
pub struct ListShareData {
    pub shares: Vec<SynoFileInfo>,
}

/// Sentinel path stored in the inode cache for the virtual root (the share listing).
#[cfg(target_os = "linux")]
pub const VIRTUAL_ROOT_PATH: &str = "";

/// GetInfo response data
#[derive(Debug, Deserialize)]
pub struct GetInfoData {
    pub files: Vec<SynoFileInfo>,
}

/// CreateFolder response data
#[derive(Debug, Deserialize)]
pub struct CreateFolderData {
    pub folders: Vec<SynoFileInfo>,
}

/// Rename response data
#[derive(Debug, Deserialize)]
pub struct RenameData {
    pub files: Vec<SynoFileInfo>,
}

/// Upload response data
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UploadData {
    pub blks: Option<serde_json::Value>,
    /// Slice-upload state: the server's partial-file handle, echoed back as
    /// `X-TMP-FILE` on the next slice. Absent on one-shot uploads.
    #[serde(default)]
    pub tmpfile: Option<String>,
}

/// An entry in the inode cache
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct InodeEntry {
    pub ino: u64,
    pub path: String,
    pub info: SynoFileInfo,
}

/// Additional fields for file/directory listings (SYNO.FileStation.List list/getinfo)
pub const ADDITIONAL_FIELDS: &str = r#"["real_path","size","owner","time","perm"]"#;

/// Additional fields for share listings (SYNO.FileStation.List list_share).
/// `size` is not a valid field for shares and some DSM versions reject it with error 400.
pub const SHARE_ADDITIONAL_FIELDS: &str = r#"["real_path","owner","time","perm"]"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_normal_file_info() {
        let json = r#"{
            "name": "video.mp4",
            "path": "/share/video.mp4",
            "isdir": false,
            "additional": {
                "size": 123456,
                "owner": {"uid": 1000, "gid": 100, "user": "alice", "group": "users"},
                "time": {"atime": 1000, "mtime": 2000, "ctime": 3000, "crtime": 4000},
                "perm": {"posix": 493}
            }
        }"#;
        let info: SynoFileInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name, "video.mp4");
        assert_eq!(info.path, "/share/video.mp4");
        assert!(!info.isdir);
        assert!(info.code.is_none());
        assert_eq!(info.additional.unwrap().size, Some(123456));
    }

    #[test]
    fn deserialize_directory_info() {
        let json = r#"{
            "name": "docs",
            "path": "/share/docs",
            "isdir": true,
            "additional": null
        }"#;
        let info: SynoFileInfo = serde_json::from_str(json).unwrap();
        assert!(info.isdir);
        assert!(info.additional.is_none());
    }

    /// The API returns `{"code":408,"path":"/share/missing"}` (no name/isdir)
    /// when get_info is called on a path that doesn't exist or has no permission.
    #[test]
    fn deserialize_per_entry_error_code() {
        let json = r#"{"code": 408, "path": "/share/missing"}"#;
        let info: SynoFileInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.code, Some(408));
        assert_eq!(info.path, "/share/missing");
        assert_eq!(info.name, ""); // defaulted
        assert!(!info.isdir); // defaulted
    }

    #[test]
    fn deserialize_success_response_envelope() {
        let json = r#"{"success": true, "data": {"files": [
            {"name": "f.txt", "path": "/s/f.txt", "isdir": false, "additional": null}
        ]}}"#;
        let resp: SynoResponse<GetInfoData> = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert!(resp.error.is_none());
        let files = resp.data.unwrap().files;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "f.txt");
    }

    #[test]
    fn deserialize_error_response_envelope() {
        let json = r#"{"success": false, "error": {"code": 414}}"#;
        let resp: SynoResponse<GetInfoData> = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert_eq!(resp.error.unwrap().code, 414);
    }

    #[test]
    fn deserialize_get_info_with_per_entry_error() {
        // The real API response for a non-existent path:
        // success=true but files[0] has a code field instead of normal metadata.
        let json = r#"{
            "data": {"files": [{"code": 408, "path": "/fishsense_data/test"}]},
            "success": true
        }"#;
        let resp: SynoResponse<GetInfoData> = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        let file = resp.data.unwrap().files.into_iter().next().unwrap();
        assert_eq!(file.code, Some(408));
    }

    #[test]
    fn deserialize_list_share_data() {
        let json = r#"{"success": true, "data": {"shares": [
            {"name": "photos", "path": "/photos", "isdir": true, "additional": null},
            {"name": "docs",   "path": "/docs",   "isdir": true, "additional": null}
        ]}}"#;
        let resp: SynoResponse<ListShareData> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.unwrap().shares.len(), 2);
    }
}
