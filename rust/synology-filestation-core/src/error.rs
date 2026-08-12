#[cfg(target_os = "linux")]
use libc::{EACCES, EAGAIN, EEXIST, EINVAL, EIO, ENOENT, ENOSPC, ENOSYS, ENOTEMPTY};

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
    /// A login or re-login attempt failed. Carries the underlying error
    /// (typically `ApiError(400)` for bad credentials, but any DSM auth-flow
    /// error can be wrapped). Distinguishes "auth failed" from a contextually
    /// identical `ApiError(N)` originating from a non-auth call.
    LoginFailed(Box<SynoFsError>),
}

/// Platform-agnostic classification of a Synology error. This is the **single
/// source of truth** every binding derives from: the FUSE errno map (below),
/// the FFI status codes (`synology-filestation-ffi`), and the PyO3 exception
/// hierarchy (`python/synology_filestation`) all map *from* `ErrorCategory`, so
/// a DSM code lands in the same place across all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotEmpty,
    InvalidArg,
    NoSpace,
    NotSupported,
    /// DSM session id expired or unknown (code 119).
    SidExpired,
    /// System too busy / try again (code 402).
    Busy,
    /// Network/transport/parse failure with no DSM code.
    Transport,
    /// A DSM code with no more specific mapping.
    Other,
}

/// Canonical map from a raw DSM/FileStation API error code to a category.
pub fn dsm_code_to_category(code: u32) -> ErrorCategory {
    match code {
        400 => ErrorCategory::InvalidArg,              // Invalid parameter
        402 => ErrorCategory::Busy,                    // System too busy
        403 | 414 | 415 => ErrorCategory::NotFound,    // Invalid path / no such file or folder
        408 | 1805 => ErrorCategory::PermissionDenied, // No permission (list / upload)
        416 => ErrorCategory::NotEmpty,                // Directory not empty
        418 | 1101 => ErrorCategory::AlreadyExists,    // Already exists (entry / folder)
        419 | 1804 => ErrorCategory::NoSpace,          // Not enough quota
        119 => ErrorCategory::SidExpired, // Session id expired / insufficient privilege
        // 401 (unknown), 404 (indexing disabled), 1100 (create failed),
        // 1800 (upload failed), and anything unrecognised fall through.
        _ => ErrorCategory::Other,
    }
}

impl SynoFsError {
    /// The platform-agnostic [`ErrorCategory`] of this error.
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::NotFound => ErrorCategory::NotFound,
            Self::PermissionDenied => ErrorCategory::PermissionDenied,
            Self::AlreadyExists => ErrorCategory::AlreadyExists,
            Self::NotEmpty => ErrorCategory::NotEmpty,
            Self::InvalidArg => ErrorCategory::InvalidArg,
            Self::NoSpace => ErrorCategory::NoSpace,
            Self::NotSupported => ErrorCategory::NotSupported,
            Self::Io(_) => ErrorCategory::Transport,
            Self::ApiError(code) => dsm_code_to_category(*code),
            Self::LoginFailed(inner) => inner.category(),
        }
    }

    /// Whether this looks like a TLS certificate rejection, so a consumer can
    /// tell the user about the `--insecure` escape hatch instead of printing a
    /// bare transport error they cannot act on.
    ///
    /// A heuristic on the message, because `From<reqwest::Error>` flattens the
    /// whole transport failure into [`SynoFsError::Io`] and there is no kind to
    /// match on. It is pinned by a test that runs a real handshake against a
    /// real self-signed certificate, so it tracks the actual string rustls
    /// produces rather than a guess at it.
    pub fn is_tls_error(&self) -> bool {
        match self {
            Self::Io(msg) => {
                let m = msg.to_ascii_lowercase();
                m.contains("certificate")
                    || m.contains("tls")
                    || m.contains("invalid peer")
                    || m.contains("unknownissuer")
                    || m.contains("self-signed")
            }
            Self::LoginFailed(inner) => inner.is_tls_error(),
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn to_errno(&self) -> i32 {
        // A failed (re)login is always a permission/auth problem to the kernel,
        // regardless of the inner DSM code.
        if matches!(self, Self::LoginFailed(_)) {
            return EACCES;
        }
        category_to_errno(self.category())
    }
}

#[cfg(target_os = "linux")]
fn category_to_errno(category: ErrorCategory) -> i32 {
    match category {
        ErrorCategory::NotFound => ENOENT,
        ErrorCategory::PermissionDenied | ErrorCategory::SidExpired => EACCES,
        ErrorCategory::AlreadyExists => EEXIST,
        ErrorCategory::NotEmpty => ENOTEMPTY,
        ErrorCategory::InvalidArg => EINVAL,
        ErrorCategory::NoSpace => ENOSPC,
        ErrorCategory::NotSupported => ENOSYS,
        ErrorCategory::Busy => EAGAIN,
        ErrorCategory::Transport | ErrorCategory::Other => EIO,
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
            Self::LoginFailed(inner) => write!(f, "login failed: {}", inner),
        }
    }
}

impl std::error::Error for SynoFsError {}

impl From<reqwest::Error> for SynoFsError {
    fn from(e: reqwest::Error) -> Self {
        // reqwest's own Display is just "error sending request for url (…)" —
        // what actually went wrong (TLS handshake rejected, connection refused,
        // DNS failure) is one or more levels down the source chain. Flattening
        // it in is the difference between a user seeing "certificate is not
        // trusted by the operating system" and seeing nothing they can act on.
        //
        // Redacted here, on the way in, rather than at each place the message is
        // shown: once the string is inside the error it gets logged, wrapped,
        // returned across the FFI and raised as a Python exception, and only one
        // of those paths would remember to scrub it. reqwest embeds the full
        // request URL — query string included — so without this every transport
        // failure publishes the session id.
        Self::Io(crate::redact::redact_secrets(&flatten_sources(&e)))
    }
}

/// Render an error together with its whole `source()` chain, `outer: inner: …`.
fn flatten_sources(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut src = err.source();
    while let Some(s) = src {
        let text = s.to_string();
        // Skip links that just restate their parent (reqwest wraps some errors
        // in a same-message shell).
        if !msg.ends_with(&text) {
            msg.push_str(": ");
            msg.push_str(&text);
        }
        src = s.source();
    }
    msg
}

impl From<serde_json::Error> for SynoFsError {
    fn from(e: serde_json::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    #[test]
    fn display_all_variants() {
        assert_eq!(SynoFsError::NotFound.to_string(), "not found");
        assert_eq!(
            SynoFsError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(SynoFsError::AlreadyExists.to_string(), "already exists");
        assert_eq!(SynoFsError::NotEmpty.to_string(), "directory not empty");
        assert_eq!(SynoFsError::InvalidArg.to_string(), "invalid argument");
        assert_eq!(SynoFsError::NoSpace.to_string(), "no space left");
        assert_eq!(SynoFsError::NotSupported.to_string(), "not supported");
        assert_eq!(
            SynoFsError::Io("detail".into()).to_string(),
            "I/O error: detail"
        );
        assert_eq!(
            SynoFsError::ApiError(408).to_string(),
            "Synology API error 408"
        );
    }

    #[test]
    fn dsm_codes_map_to_expected_categories() {
        // The single source of truth shared by errno / FFI / PyO3. 119 in
        // particular must be SidExpired so all three bindings agree.
        assert_eq!(dsm_code_to_category(119), ErrorCategory::SidExpired);
        assert_eq!(dsm_code_to_category(400), ErrorCategory::InvalidArg);
        assert_eq!(dsm_code_to_category(402), ErrorCategory::Busy);
        assert_eq!(dsm_code_to_category(403), ErrorCategory::NotFound);
        assert_eq!(dsm_code_to_category(408), ErrorCategory::PermissionDenied);
        assert_eq!(dsm_code_to_category(416), ErrorCategory::NotEmpty);
        assert_eq!(dsm_code_to_category(418), ErrorCategory::AlreadyExists);
        assert_eq!(dsm_code_to_category(419), ErrorCategory::NoSpace);
        assert_eq!(dsm_code_to_category(9999), ErrorCategory::Other);
        assert_eq!(
            SynoFsError::ApiError(119).category(),
            ErrorCategory::SidExpired
        );
        assert_eq!(
            SynoFsError::NotSupported.category(),
            ErrorCategory::NotSupported
        );
    }

    #[test]
    fn from_serde_json_error_gives_io_variant() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let syno: SynoFsError = json_err.into();
        assert!(matches!(syno, SynoFsError::Io(_)));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn named_variants_map_to_expected_errno() {
        assert_eq!(SynoFsError::NotFound.to_errno(), ENOENT);
        assert_eq!(SynoFsError::PermissionDenied.to_errno(), EACCES);
        assert_eq!(SynoFsError::AlreadyExists.to_errno(), EEXIST);
        assert_eq!(SynoFsError::NotEmpty.to_errno(), ENOTEMPTY);
        assert_eq!(SynoFsError::InvalidArg.to_errno(), EINVAL);
        assert_eq!(SynoFsError::NoSpace.to_errno(), ENOSPC);
        assert_eq!(SynoFsError::NotSupported.to_errno(), ENOSYS);
        assert_eq!(SynoFsError::Io("oops".into()).to_errno(), EIO);
    }

    #[test]
    fn known_api_codes_map_correctly() {
        let cases = [
            (400, EINVAL),
            (402, EAGAIN),
            (403, ENOENT),
            (408, EACCES),
            (414, ENOENT),
            (415, ENOENT),
            (416, ENOTEMPTY),
            (418, EEXIST),
            (419, ENOSPC),
            (1101, EEXIST),
            (1804, ENOSPC),
            (1805, EACCES),
        ];
        for (code, expected) in cases {
            assert_eq!(
                SynoFsError::ApiError(code).to_errno(),
                expected,
                "API code {code} should map to errno {expected}"
            );
        }
    }

    #[test]
    fn unknown_api_code_maps_to_eio() {
        assert_eq!(SynoFsError::ApiError(9999).to_errno(), EIO);
    }

    #[test]
    fn session_privilege_code_maps_to_eacces() {
        assert_eq!(SynoFsError::ApiError(119).to_errno(), EACCES);
    }
}
