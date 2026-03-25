use libc::{EACCES, EAGAIN, EEXIST, EINVAL, EIO, ENOENT, ENOTEMPTY, ENOSPC, ENOSYS};

#[derive(Debug)]
#[allow(dead_code)]
pub enum SynoFsError {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotEmpty,
    InvalidArg,
    NoSpace,
    NotSupported,
    Io(String),
    /// Raw Synology API error code
    ApiError(u32),
}

impl SynoFsError {
    pub fn to_errno(&self) -> i32 {
        match self {
            Self::NotFound => ENOENT,
            Self::PermissionDenied => EACCES,
            Self::AlreadyExists => EEXIST,
            Self::NotEmpty => ENOTEMPTY,
            Self::InvalidArg => EINVAL,
            Self::NoSpace => ENOSPC,
            Self::NotSupported => ENOSYS,
            Self::Io(_) => EIO,
            Self::ApiError(code) => syno_code_to_errno(*code),
        }
    }
}

fn syno_code_to_errno(code: u32) -> i32 {
    match code {
        // Common FileStation errors
        400 => EINVAL,    // Invalid parameter
        401 => EIO,       // Unknown error
        402 => EAGAIN,    // System too busy
        403 => ENOENT,    // Invalid path
        404 => EIO,       // File indexing disabled
        408 => EACCES,    // No permission
        414 => ENOENT,    // No such file
        415 => ENOENT,    // No such folder
        416 => ENOTEMPTY, // Directory not empty
        418 => EEXIST,    // Already exists
        419 => ENOSPC,    // Not enough quota
        // CreateFolder-specific errors
        1100 => EIO,      // Failed to create folder
        1101 => EEXIST,   // Folder already exists
        // Upload-specific errors
        1800 => EIO,      // Upload failed
        1804 => ENOSPC,   // Not enough quota
        1805 => EACCES,   // No permission to upload
        _ => EIO,
    }
}

impl std::fmt::Display for SynoFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::AlreadyExists => write!(f, "already exists"),
            Self::NotEmpty => write!(f, "directory not empty"),
            Self::InvalidArg => write!(f, "invalid argument"),
            Self::NoSpace => write!(f, "no space left"),
            Self::NotSupported => write!(f, "not supported"),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
            Self::ApiError(code) => write!(f, "Synology API error {}", code),
        }
    }
}

impl std::error::Error for SynoFsError {}

impl From<reqwest::Error> for SynoFsError {
    fn from(e: reqwest::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for SynoFsError {
    fn from(e: serde_json::Error) -> Self {
        Self::Io(e.to_string())
    }
}
