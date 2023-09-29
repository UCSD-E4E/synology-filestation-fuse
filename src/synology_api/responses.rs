use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SynologyResult<T> {
    pub success: bool,
    pub data: T
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct LoginResult {
    pub sid: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FileStationItem<T> {
    pub isdir: bool,
    pub name: String,
    pub path: String,
    pub additional: T
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FileAdditional {
    pub size: u64,
    pub time: Time
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ShareAdditional {
    pub time: Time,
    pub volume_status: VolumeStatus
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct VolumeStatus {
    pub freespace: u64,
    pub readonly: bool,
    pub totalspace: u64
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Time {
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub crtime: u64
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ListSharesResult {
    pub offset: i32,
    pub shares: Vec<FileStationItem<ShareAdditional>>,
    pub total: i32
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ListFilesResult {
    pub offset: Option<i32>,
    pub files: Vec<FileStationItem<FileAdditional>>,
    pub total: Option<i32>
}
