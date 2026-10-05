use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Path of the agent's Unix socket. Prefers `$XDG_RUNTIME_DIR` (per-user, tmpfs,
/// cleared on logout); falls back to the system temp dir.
pub fn socket_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("easysign-agent.sock");
        }
    }
    std::env::temp_dir().join("easysign-agent.sock")
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgoId {
    Sha256Rsa,
    Sha512Rsa,
    /// Raw RSA: `hash` is an already-built DigestInfo/EMSA block.
    RawRsa,
}

/// An account = one phone number (userID) that may hold several certificates.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileInfo {
    pub name: String,
    pub user_id: String,
    pub num_certs: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    ListProfiles,
    AddProfile {
        name: Option<String>,
        user_id: String,
        /// Also write it to the config file so it survives restarts.
        persist: bool,
    },
    RemoveProfile {
        name: String,
    },
    ListCerts,
    GetCert {
        credential_id: Option<String>,
    },
    Sign {
        credential_id: Option<String>,
        hash: Vec<u8>,
        algo: AlgoId,
    },
    /// Drop the cached password and SADs. `name = None` clears every profile.
    Logout {
        name: Option<String>,
    },
    /// Sent by the client in reply to `Response::NeedCredentials` to continue a
    /// pending `Sign` on the same connection.
    Credentials {
        /// Present only when the agent asked for the password (not cached yet).
        password: Option<String>,
        otp: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertEntry {
    pub credential_id: String,
    /// The account (profile) name this certificate belongs to.
    pub account: String,
    /// Human-readable description (subject CN + expiry), if the cert parsed.
    pub label: Option<String>,
    pub der: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Profiles(Vec<ProfileInfo>),
    Certs(Vec<CertEntry>),
    Cert(CertEntry),
    Signature(Vec<u8>),
    /// The agent needs credentials to authorize a pending `Sign`. The client must
    /// reply with `Request::Credentials` on the same connection. An OTP has already
    /// been sent by SMS. `ask_password` is false when the password is still cached.
    NeedCredentials {
        ask_password: bool,
        label: String,
    },
    Ok,
    Error(String),
}

fn invalid_data<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let data = serde_json::to_vec(msg).map_err(invalid_data)?;
    w.write_all(&data)?;
    w.write_all(b"\n")?;
    w.flush()
}

pub fn read_msg<R: BufRead, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&line).map_err(invalid_data)?))
}
