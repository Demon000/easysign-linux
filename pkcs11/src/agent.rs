use ipc::{AlgoId, CertEntry, Request, Response};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::process::Command;

fn connect() -> Result<UnixStream, String> {
    UnixStream::connect(ipc::socket_path())
        .map_err(|e| format!("cannot reach easysign-agent: {e}"))
}

pub fn list_certs() -> Result<Vec<CertEntry>, String> {
    let s = connect()?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    ipc::write_msg(&mut w, &Request::ListCerts).map_err(|e| e.to_string())?;
    match ipc::read_msg::<_, Response>(&mut r).map_err(|e| e.to_string())? {
        Some(Response::Certs(c)) => Ok(c),
        Some(Response::Error(e)) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

pub fn sign(credential_id: &str, hash: Vec<u8>, algo: AlgoId) -> Result<Vec<u8>, String> {
    let s = connect()?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    ipc::write_msg(
        &mut w,
        &Request::Sign {
            credential_id: Some(credential_id.to_string()),
            hash,
            algo,
        },
    )
    .map_err(|e| e.to_string())?;
    loop {
        match ipc::read_msg::<_, Response>(&mut r).map_err(|e| e.to_string())? {
            Some(Response::Signature(sig)) => return Ok(sig),
            Some(Response::Error(e)) => return Err(e),
            Some(Response::NeedCredentials { ask_password, label }) => {
                let (password, otp) = prompt(ask_password, &label)?;
                ipc::write_msg(&mut w, &Request::Credentials { password, otp })
                    .map_err(|e| e.to_string())?;
            }
            _ => return Err("unexpected response".into()),
        }
    }
}

/// Graphical credential prompt (Chrome has no terminal). Single-field `zenity
/// --entry` dialogs so Enter submits (zenity --forms ignores Enter). The password
/// box appears only the first time per session; afterwards it is just the OTP.
fn prompt(ask_password: bool, label: &str) -> Result<(Option<String>, String), String> {
    let password = if ask_password {
        Some(zenity_entry(&format!("Signature password for {label}"), true)?)
    } else {
        None
    };
    let otp = zenity_entry(&format!("Sign in to {label}\nEnter the OTP received by SMS"), false)?
        .trim()
        .to_string();
    Ok((password, otp))
}

fn zenity_entry(text: &str, hide: bool) -> Result<String, String> {
    let mut args = vec!["--entry", "--title=EasySign", "--text", text];
    if hide {
        args.push("--hide-text");
    }
    let out = Command::new("zenity")
        .args(&args)
        .output()
        .map_err(|e| format!("zenity: {e}"))?;
    if !out.status.success() {
        return Err("prompt cancelled".into());
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.strip_suffix('\n').unwrap_or(&s).to_string())
}
