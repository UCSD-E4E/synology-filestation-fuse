//! FileStation logical path → SMB (share, share-relative path) decomposition.
//!
//! FileStation speaks logical paths like `/fishsense_data/REEF/x.orf`; SMB
//! addresses the same bytes as a **share** (`fishsense_data`) plus a
//! share-relative path (`REEF/x.orf`). The share is always the first path
//! component — so no mount-root mapping config is needed, unlike an OS mount.
//!
//! Paths stay forward-slash separated here; the `smb2` layer converts `/` → `\`
//! on the wire.

use synology_filestation_core::SynoFsError;

/// An SMB location: a share name plus a share-relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbPath {
    /// SMB share name (the first component of the logical path).
    pub share: String,
    /// Share-relative path (forward-slash separated). Empty = the share root.
    pub path: String,
}

impl SmbPath {
    /// Decompose a FileStation logical path into `(share, relative path)`.
    ///
    /// A leading slash is optional and a trailing slash is trimmed. The
    /// remainder may be empty (the share root). Returns
    /// [`SynoFsError::InvalidArg`] when there is no share component
    /// (`""`, `"/"`, all-slashes).
    pub fn from_logical(logical: &str) -> Result<Self, SynoFsError> {
        let trimmed = logical.trim_matches('/');
        if trimmed.is_empty() {
            return Err(SynoFsError::InvalidArg);
        }
        let (share, path) = match trimmed.split_once('/') {
            Some((s, p)) => (s, p),
            None => (trimmed, ""),
        };
        if share.is_empty() {
            return Err(SynoFsError::InvalidArg);
        }
        Ok(SmbPath {
            share: share.to_string(),
            path: path.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(logical: &str) -> SmbPath {
        SmbPath::from_logical(logical).expect("should decompose")
    }

    #[test]
    fn nested_path_with_leading_slash() {
        let p = ok("/fishsense_data/REEF/data/x.orf");
        assert_eq!(p.share, "fishsense_data");
        assert_eq!(p.path, "REEF/data/x.orf");
    }

    #[test]
    fn leading_slash_is_optional_and_equivalent() {
        assert_eq!(ok("/share/sub/f"), ok("share/sub/f"));
    }

    #[test]
    fn share_root_has_empty_path() {
        assert_eq!(
            ok("/photos"),
            SmbPath {
                share: "photos".into(),
                path: "".into()
            }
        );
    }

    #[test]
    fn trailing_slash_is_trimmed() {
        assert_eq!(ok("/photos/"), ok("/photos"));
        assert_eq!(ok("/photos/2026/"), ok("/photos/2026"));
    }

    #[test]
    fn spaces_in_path_are_preserved() {
        // The real REEF path has a space — must survive verbatim (SMB paths
        // allow spaces; the smb2 layer handles the `/`→`\` conversion).
        let p = ok("/fishsense_data/REEF/08_2023/080123_FSL-01 Photos/P8010001.ORF");
        assert_eq!(p.share, "fishsense_data");
        assert_eq!(p.path, "REEF/08_2023/080123_FSL-01 Photos/P8010001.ORF");
    }

    #[test]
    fn empty_and_root_are_invalid() {
        assert!(matches!(
            SmbPath::from_logical(""),
            Err(SynoFsError::InvalidArg)
        ));
        assert!(matches!(
            SmbPath::from_logical("/"),
            Err(SynoFsError::InvalidArg)
        ));
        assert!(matches!(
            SmbPath::from_logical("///"),
            Err(SynoFsError::InvalidArg)
        ));
    }
}
