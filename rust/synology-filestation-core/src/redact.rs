//! Scrubbing secrets out of text that is about to be logged, returned in an
//! error, or shown to a user.
//!
//! The session id travels as a `_sid` query parameter on every FileStation
//! call, and `reqwest` puts the **full request URL, query string included**,
//! into the `Display` of any transport error. So a single connection refusal
//! produces:
//!
//! ```text
//! error sending request for url (https://nas:5001/webapi/entry.cgi?api=…&_sid=SECRET)
//! ```
//!
//! which then reaches the CLI's stderr, the GUI's log pane (via the FFI log
//! bridge), and the message of every Python exception. A session id is a
//! bearer token: whoever reads it out of a log can act as that user until it
//! expires.
//!
//! This module is the last line of defence, not the first. The client prefers
//! to keep the session id out of URLs altogether (see `SessionAuth` in
//! `client.rs`); redaction is what catches the cases where it cannot — a
//! fallback to query auth, a URL logged by some dependency, a parameter added
//! later by somebody who did not read this file.

/// Parameter names whose values must never survive into a log or an error.
///
/// Matched case-insensitively against the identifier immediately preceding an
/// `=`, so it covers query strings (`&_sid=…`), form bodies (`passwd=…`), and
/// most incidental `key=value` renderings.
const SECRET_PARAMS: &[&str] = &[
    "_sid",
    "sid",
    "passwd",
    "password",
    "otp_code",
    "otp",
    "synotoken",
    "x-syno-token",
];

/// What replaces a redacted value. Deliberately visible: a reader should be
/// able to tell that something was removed rather than wonder whether the
/// parameter was empty.
const PLACEHOLDER: &str = "<redacted>";

/// True if `name` is a parameter whose value is a secret.
fn is_secret(name: &str) -> bool {
    SECRET_PARAMS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// Characters that end a parameter value in the shapes we care about: query
/// strings, form bodies, and values embedded in prose or parenthesised URLs.
fn ends_value(c: char) -> bool {
    matches!(
        c,
        '&' | '"' | '\'' | ')' | ' ' | ',' | ';' | '\n' | '\r' | '\t'
    )
}

/// Replace the value of every secret-looking `key=value` pair with a
/// placeholder, leaving everything else — including the key itself — intact so
/// the message stays diagnosable.
pub fn redact_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < text.len() {
        let Some(rel) = text[cursor..].find('=') else {
            out.push_str(&text[cursor..]);
            return out;
        };
        let eq = cursor + rel;

        // The parameter name is the identifier run ending at the '='.
        // `rfind` reports the byte where the delimiter *starts*; stepping past it
        // means adding that character's own width, not 1. Adding 1 lands inside
        // any multi-byte delimiter and panics the slice below — and a NAS path
        // with an accent in it is enough to get one here.
        let name_start = text[..eq]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
            .map(|(idx, c)| idx + c.len_utf8())
            .unwrap_or(0);
        let name = &text[name_start..eq];

        out.push_str(&text[cursor..=eq]);
        cursor = eq + 1;

        if is_secret(name) {
            let value_end = text[cursor..]
                .find(ends_value)
                .map(|rel| cursor + rel)
                .unwrap_or(text.len());
            // An already-empty value stays empty rather than being dressed up
            // as a redacted one.
            if value_end > cursor {
                out.push_str(PLACEHOLDER);
            }
            cursor = value_end;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape reqwest produces. Pinned as a literal because this is
    /// the string that actually reaches a log file.
    #[test]
    fn redacts_the_session_id_from_a_reqwest_error_url() {
        let leaked = "error sending request for url \
             (https://nas:5001/webapi/entry.cgi?api=SYNO.FileStation.List&version=2&_sid=abc123SECRET): \
             client error (Connect): tcp connect error";

        let safe = redact_secrets(leaked);

        assert!(!safe.contains("abc123SECRET"), "{safe}");
        assert!(safe.contains("_sid=<redacted>"), "{safe}");
        // Everything diagnostic survives.
        assert!(safe.contains("SYNO.FileStation.List"), "{safe}");
        assert!(safe.contains("tcp connect error"), "{safe}");
        assert!(safe.contains("nas:5001"), "{safe}");
    }

    #[test]
    fn redacts_credentials_from_a_form_body() {
        let body = "api=SYNO.API.Auth&account=alice&passwd=hunter2&otp_code=998877&format=sid";
        let safe = redact_secrets(body);

        assert!(!safe.contains("hunter2"), "{safe}");
        assert!(!safe.contains("998877"), "{safe}");
        assert!(safe.contains("passwd=<redacted>"), "{safe}");
        assert!(safe.contains("otp_code=<redacted>"), "{safe}");
        // The account name is not a secret and is useful for diagnosis.
        assert!(safe.contains("account=alice"), "{safe}");
    }

    #[test]
    fn leaves_ordinary_parameters_untouched() {
        let text = "path=/share/file.txt&offset=0&length=1024";
        assert_eq!(redact_secrets(text), text);
    }

    /// `sid` must not match `_sidecar`, `considered=`, and friends — the name
    /// is the whole identifier before the `=`, not a substring of it.
    #[test]
    fn only_matches_whole_parameter_names() {
        let text = "sidecar=keepme&considered=keepme2&nosid=keepme3";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn redacts_every_occurrence() {
        let text = "a?_sid=one&b&_sid=two";
        let safe = redact_secrets(text);
        assert!(!safe.contains("one"), "{safe}");
        assert!(!safe.contains("two"), "{safe}");
    }

    #[test]
    fn is_idempotent() {
        let once = redact_secrets("url?_sid=secret");
        assert_eq!(redact_secrets(&once), once);
    }

    #[test]
    fn matches_case_insensitively() {
        assert!(!redact_secrets("?_SID=secret").contains("secret"));
        assert!(!redact_secrets("?Passwd=secret").contains("secret"));
    }

    /// Byte-index arithmetic must not split a multi-byte character.
    #[test]
    fn handles_multibyte_text_without_panicking() {
        let text = "café=ok&_sid=secret&naïve=ok — ✓";
        let safe = redact_secrets(text);
        assert!(!safe.contains("secret"), "{safe}");
        assert!(safe.contains("café=ok"), "{safe}");
        assert!(safe.contains('✓'), "{safe}");
    }

    #[test]
    fn empty_value_stays_empty() {
        assert_eq!(redact_secrets("?_sid=&api=x"), "?_sid=&api=x");
    }

    #[test]
    fn text_with_no_parameters_is_unchanged() {
        let text = "connection refused (os error 111)";
        assert_eq!(redact_secrets(text), text);
    }
}
