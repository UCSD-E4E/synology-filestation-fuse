//! Reading the `.ovpn` file.
//!
//! `synology-filestation-connect` already fetches this from the `installers`
//! share; nothing until now read it. Everything a session needs is in it — the
//! address to dial, the certificate chain to trust, the `tls-auth` key and
//! which half of it we sign with — and all of it is written by the
//! `synology_vpn` role from `spec/e4e-nas/vpn.yml`, so the shape is known
//! rather than guessed.
//!
//! Two rules about what to do with a directive we do not implement, and the
//! difference between them matters:
//!
//! * an option that changes *how the wire looks* — a different transport, a
//!   compression scheme — is refused, because carrying on regardless produces
//!   a tunnel that comes up and moves nothing;
//! * an option that changes nothing we do — `verb`, `nobind`, `persist-key` —
//!   is ignored, and there is no point listing them.
//!
//! The file embeds `ta.key`, which makes it a shared secret rather than a
//! public document. Nothing here logs its contents, and the parsed key is
//! zeroized like every other.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::session::{Credentials, SessionConfig};
use crate::static_key::{KeyDirection, StaticKey};
use crate::Error;

/// What a `.ovpn` says.
pub struct Profile {
    /// The name to dial. Public, and not the address inside the tunnel.
    pub remote: String,
    pub port: u16,
    /// The chain that replaces the system trust store.
    pub ca_pem: String,
    pub static_key: Option<StaticKey>,
    pub key_direction: KeyDirection,
    /// The name the server's certificate must carry, from
    /// `verify-x509-name`.
    pub server_name: String,
    /// Whether the server will ask for a username and password.
    pub wants_credentials: bool,
}

impl Profile {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut remote = None;
        let mut port = 1194;
        let mut key_direction = KeyDirection::Bidirectional;
        let mut verify_name = None;

        for line in directives(text) {
            let mut words = line.split_whitespace();
            let Some(name) = words.next() else { continue };
            let rest: Vec<&str> = words.collect();

            match (name, rest.as_slice()) {
                ("remote", [host]) => remote = Some((*host).to_string()),
                ("remote", [host, given]) => {
                    remote = Some((*host).to_string());
                    port = given
                        .parse()
                        .map_err(|_| Error::BadProfile(line.to_string()))?;
                }
                ("proto", [protocol]) => {
                    // TCP is a different framing, and this client speaks one
                    // of them. Refusing beats connecting and going quiet.
                    if !protocol.eq_ignore_ascii_case("udp") {
                        return Err(Error::UnsupportedProfileOption(line.to_string()));
                    }
                }
                ("key-direction", [direction]) => {
                    key_direction = match *direction {
                        "0" => KeyDirection::Normal,
                        "1" => KeyDirection::Inverse,
                        _ => return Err(Error::BadProfile(line.to_string())),
                    }
                }
                ("verify-x509-name", [name, ..]) => verify_name = Some((*name).to_string()),
                ("cipher" | "data-ciphers", [name, ..]) => {
                    if !name.eq_ignore_ascii_case(crate::SUPPORTED_CIPHER) {
                        return Err(Error::UnsupportedCipher((*name).to_string()));
                    }
                }
                // Compression changes the framing of every payload, and this
                // client implements none of it.
                ("comp-lzo", ["no"]) => {}
                ("comp-lzo" | "compress", _) => {
                    return Err(Error::UnsupportedCompression(line.to_string()))
                }
                // A profile that expects a client certificate is one this
                // client cannot satisfy on its own, and saying so beats
                // failing inside a TLS handshake.
                ("cert" | "pkcs12", _) => {
                    return Err(Error::UnsupportedProfileOption(line.to_string()))
                }
                _ => {}
            }
        }

        let remote = remote.ok_or_else(|| Error::BadProfile("no remote".into()))?;
        let ca_pem = block(text, "ca").ok_or_else(|| Error::BadProfile("no <ca> block".into()))?;
        let static_key = match block(text, "tls-auth") {
            Some(key) => Some(StaticKey::parse(&key)?),
            None => None,
        };

        Ok(Self {
            // Falling back to the remote: `verify-x509-name` names the same
            // host in the published profile, and a profile without it still
            // has to verify against something.
            server_name: verify_name.unwrap_or_else(|| remote.clone()),
            remote,
            port,
            ca_pem,
            static_key,
            key_direction,
            wants_credentials: directives(text).any(|line| line == "auth-user-pass"),
        })
    }

    /// Everything a session needs, once the credentials are known.
    pub fn into_config(self, credentials: Option<Credentials>) -> Result<SessionConfig, Error> {
        let static_key = self
            .static_key
            .ok_or_else(|| Error::BadProfile("no <tls-auth> block".into()))?;

        let mut config = SessionConfig::new(self.ca_pem, self.server_name, static_key);
        config.key_direction = self.key_direction;
        config.credentials = credentials;
        config.tls_timeout = Duration::from_secs(2);
        Ok(config)
    }
}

/// The directives, with comments and inline blocks left out.
fn directives(text: &str) -> impl Iterator<Item = &str> {
    let mut inside = false;
    text.lines().filter_map(move |line| {
        let line = line.trim();
        if line.starts_with('<') {
            inside = !line.starts_with("</");
            return None;
        }
        if inside || line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return None;
        }
        Some(line)
    })
}

/// The contents of an inline `<name>…</name>` block.
fn block(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let (_, rest) = text.split_once(&open)?;
    let (body, _) = rest.split_once(&close)?;
    Some(body.trim_start_matches(['\r', '\n']).to_string())
}

/// A password read from a file, as `auth-user-pass <file>` would supply it.
///
/// Kept out of `Profile`: a profile is a document that may be shared with
/// every user of the VPN, and a credential is not.
pub fn credentials(username: impl Into<String>, password: impl Into<String>) -> Credentials {
    Credentials {
        username: username.into(),
        password: Zeroizing::new(password.into()),
    }
}
