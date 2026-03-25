use serde::Deserialize;

/// One file or directory returned by SYNO.FileStation.List
#[derive(Debug, Clone, Deserialize)]
pub struct SynoFileInfo {
    pub name: String,
    pub path: String,
    pub isdir: bool,
    pub additional: Option<SynoAdditional>,
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct SynoTime {
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: i64,
}

#[derive(Debug, Clone, Deserialize)]
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
}

/// An entry in the inode cache
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
