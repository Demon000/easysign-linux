use anyhow::{bail, Context, Result};
use base64::Engine;
use csc::{algo, Client, CredentialInfo};
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Write};
use std::os::unix::net::UnixStream;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "list" => cmd_list(),
        "info" => cmd_info(args.get(1).map(String::as_str)),
        "cert" => cmd_cert(&args[1..]),
        "test-sign" => cmd_test_sign(&args[1..]),
        "profile" => cmd_profile(&args[1..]),
        "certs" => cmd_certs(),
        "agent-status" => cmd_agent_status(),
        "agent-sign" => cmd_agent_sign(&args[1..]),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    eprintln!(
        "easysign - Trans Sped mSign cloud signature diagnostics\n\n\
         USAGE:\n  \
         easysign list                       list credential IDs (Aliases) for a phone\n  \
         easysign info [credentialID]        show SCAL/authMode and save the cert\n  \
         easysign cert [credentialID] --out F.pem   save the leaf certificate (PEM)\n  \
         easysign test-sign [credentialID] [--message TEXT]   full sign round-trip\n  \
         easysign profile list               list accounts held by the agent\n  \
         easysign profile add <phone> [--name N]   import an account's certs\n  \
         easysign profile remove <name>      drop an account\n  \
         easysign certs                      list all certificates (descriptive)\n  \
         easysign agent-status               same as 'profile list'\n  \
         easysign agent-sign [--cred ID] [--message TEXT]   sign a test hash via the agent\n\n\
         The phone number (userID, e.g. +407...) may be set via EASYSIGN_USER.\n\
         list/info/cert need only the phone; test-sign also asks for the\n\
         signature password (PIN) and the SMS OTP."
    );
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn phone() -> Result<String> {
    match std::env::var("EASYSIGN_USER") {
        Ok(u) if !u.is_empty() => Ok(u),
        _ => prompt("Phone (userID, +407...)"),
    }
}

fn pick_credential(client: &Client, user_id: &str, given: Option<&str>) -> Result<String> {
    if let Some(id) = given {
        return Ok(id.to_string());
    }
    let ids = client.credentials_list(user_id)?;
    match ids.len() {
        0 => bail!("no credentials for this phone number"),
        1 => Ok(ids.into_iter().next().unwrap()),
        _ => {
            eprintln!("multiple credentials (Aliases); pass one explicitly:");
            for id in &ids {
                eprintln!("  {id}");
            }
            bail!("ambiguous credentialID");
        }
    }
}

fn cmd_list() -> Result<()> {
    let client = Client::msign();
    let user = phone()?;
    let ids = client.credentials_list(&user)?;
    if ids.is_empty() {
        eprintln!("(no credentials for {user})");
    }
    for id in ids {
        println!("{id}");
    }
    Ok(())
}

fn cmd_info(cred: Option<&str>) -> Result<()> {
    let client = Client::msign();
    let user = phone()?;
    let id = pick_credential(&client, &user, cred)?;
    let info = client.credentials_info(&id)?;
    print_info(&info);
    if let Some(der) = info.cert_chain_der.first() {
        let path = "easysign-cert.pem";
        std::fs::write(path, pem_cert(der))?;
        println!("leaf certificate saved to {path}");
        println!("inspect with: openssl x509 -in {path} -noout -subject -issuer -dates");
    }
    Ok(())
}

fn cmd_cert(args: &[String]) -> Result<()> {
    let (cred, out) = parse_cred_and_flag(args, "--out", "easysign-cert.pem")?;
    let client = Client::msign();
    let user = phone()?;
    let id = pick_credential(&client, &user, cred.as_deref())?;
    let info = client.credentials_info(&id)?;
    let der = info
        .cert_chain_der
        .first()
        .context("no certificate returned")?;
    std::fs::write(&out, pem_cert(der))?;
    println!("leaf certificate saved to {out}");
    Ok(())
}

fn cmd_test_sign(args: &[String]) -> Result<()> {
    let mut cred: Option<String> = None;
    let mut message = "easysign-linux test".to_string();
    let mut reuse_sad: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--message" => {
                message = args.get(i + 1).context("--message needs text")?.clone();
                i += 2;
            }
            "--sad" => {
                reuse_sad = Some(args.get(i + 1).context("--sad needs a value")?.clone());
                i += 2;
            }
            other => {
                cred = Some(other.to_string());
                i += 1;
            }
        }
    }

    let client = Client::msign();
    let user = phone()?;
    let id = pick_credential(&client, &user, cred.as_deref())?;
    let info = client.credentials_info(&id)?;
    print_info(&info);

    let digest = Sha256::digest(message.as_bytes());
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    let hashes = vec![hash_b64];

    let sad_value = match reuse_sad {
        Some(s) => {
            println!("reusing provided SAD (no new OTP)");
            s
        }
        None => {
            println!("requesting OTP (SMS)...");
            client.send_otp(&id)?;
            let password = rpassword::prompt_password("Signature password (PIN): ")?;
            let otp = prompt("OTP (from SMS)")?;
            let sad = client
                .authorize(&id, 1, &hashes, &password, &otp)
                .context("authorize failed")?;
            println!(
                "SAD obtained (expiresIn={}): {}",
                sad.expires_in
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                sad.sad
            );
            println!("(retry signing without a new OTP: easysign test-sign --sad '{}')", sad.sad);
            sad.sad
        }
    };

    let sigs = client
        .sign_hash(&id, &sad_value, &hashes, algo::SHA256_RSA)
        .context("signHash failed")?;
    let sig = sigs.first().context("no signature returned")?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    println!("signature ({} bytes): {sig_b64}", sig.len());

    if let Some(der) = info.cert_chain_der.first() {
        std::fs::write("easysign-cert.pem", pem_cert(der))?;
        std::fs::write("easysign-sig.bin", sig)?;
        std::fs::write("easysign-msg.txt", &message)?;
        println!("\nverify with:");
        println!("  openssl x509 -in easysign-cert.pem -pubkey -noout > pub.pem");
        println!("  openssl dgst -sha256 -verify pub.pem -signature easysign-sig.bin easysign-msg.txt");
    }
    Ok(())
}

fn agent_call(req: &ipc::Request) -> Result<ipc::Response> {
    let path = ipc::socket_path();
    let stream = UnixStream::connect(&path)
        .with_context(|| format!("connect {} (is easysign-agent running?)", path.display()))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    ipc::write_msg(&mut writer, req)?;
    ipc::read_msg::<_, ipc::Response>(&mut reader)?.context("agent closed connection")
}

/// Sign via the agent, answering its credential prompts here in the terminal.
fn sign_via_agent(credential_id: String, hash: Vec<u8>, algo: ipc::AlgoId) -> Result<Vec<u8>> {
    let path = ipc::socket_path();
    let stream = UnixStream::connect(&path)
        .with_context(|| format!("connect {} (is easysign-agent running?)", path.display()))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    ipc::write_msg(
        &mut writer,
        &ipc::Request::Sign {
            credential_id: Some(credential_id),
            hash,
            algo,
        },
    )?;
    loop {
        match ipc::read_msg::<_, ipc::Response>(&mut reader)?.context("agent closed connection")? {
            ipc::Response::Signature(s) => return Ok(s),
            ipc::Response::Error(e) => bail!("agent error: {e}"),
            ipc::Response::NeedCredentials { ask_password, label } => {
                let password = if ask_password {
                    Some(rpassword::prompt_password(format!(
                        "Signature password for {label}: "
                    ))?)
                } else {
                    None
                };
                let otp = prompt("OTP (SMS)")?;
                ipc::write_msg(&mut writer, &ipc::Request::Credentials { password, otp })?;
            }
            other => bail!("unexpected response: {other:?}"),
        }
    }
}

fn list_profiles() -> Result<Vec<ipc::ProfileInfo>> {
    match agent_call(&ipc::Request::ListProfiles)? {
        ipc::Response::Profiles(p) => Ok(p),
        ipc::Response::Error(e) => bail!("agent error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn list_certs() -> Result<Vec<ipc::CertEntry>> {
    match agent_call(&ipc::Request::ListCerts)? {
        ipc::Response::Certs(c) => Ok(c),
        ipc::Response::Error(e) => bail!("agent error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn cmd_agent_status() -> Result<()> {
    let profiles = list_profiles()?;
    if profiles.is_empty() {
        println!("(no accounts; add one: easysign profile add <phone>)");
    }
    for p in profiles {
        println!("{:<12} {:<16} {} cert(s)", p.name, p.user_id, p.num_certs);
    }
    Ok(())
}

fn cmd_certs() -> Result<()> {
    let certs = list_certs()?;
    if certs.is_empty() {
        println!("(no certificates; add an account: easysign profile add <phone>)");
    }
    for c in certs {
        println!("{}", c.label.as_deref().unwrap_or("(unparsed certificate)"));
        println!("    {}  [{}]", c.credential_id, c.account);
    }
    Ok(())
}

fn cmd_profile(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("list") | None => cmd_agent_status(),
        Some("add") => {
            let mut name: Option<String> = None;
            let mut user_id: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--name" {
                    name = Some(args.get(i + 1).context("--name needs a value")?.clone());
                    i += 2;
                } else {
                    user_id = Some(args[i].clone());
                    i += 1;
                }
            }
            let user_id = user_id.context("usage: easysign profile add <phone> [--name NAME]")?;
            match agent_call(&ipc::Request::AddProfile {
                name,
                user_id,
                persist: true,
            })? {
                ipc::Response::Profiles(ps) => {
                    println!("added. accounts now:");
                    for p in ps {
                        println!("  {:<12} {:<16} {} cert(s)", p.name, p.user_id, p.num_certs);
                    }
                    Ok(())
                }
                ipc::Response::Error(e) => bail!("agent error: {e}"),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Some("remove") => {
            let name = args
                .get(1)
                .context("usage: easysign profile remove <name>")?
                .clone();
            match agent_call(&ipc::Request::RemoveProfile { name })? {
                ipc::Response::Ok => {
                    println!("removed");
                    Ok(())
                }
                ipc::Response::Error(e) => bail!("agent error: {e}"),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        Some(x) => bail!("unknown profile subcommand: {x}"),
    }
}

/// Resolve which certificate to use: an explicit `--cred`, the only one, or a
/// numbered terminal picker.
fn choose_credential(explicit: Option<String>) -> Result<String> {
    if let Some(c) = explicit {
        return Ok(c);
    }
    let certs = list_certs()?;
    match certs.len() {
        0 => bail!("no certificates; add an account: easysign profile add <phone>"),
        1 => Ok(certs.into_iter().next().unwrap().credential_id),
        _ => {
            println!("Select a certificate:");
            for (i, c) in certs.iter().enumerate() {
                println!(
                    "  {}) {}  [{}]",
                    i + 1,
                    c.label.as_deref().unwrap_or(&c.credential_id),
                    c.account
                );
            }
            let choice = prompt(&format!("Which? [1-{}]", certs.len()))?;
            let idx: usize = choice
                .parse()
                .ok()
                .filter(|n| (1..=certs.len()).contains(n))
                .context("invalid selection")?;
            Ok(certs[idx - 1].credential_id.clone())
        }
    }
}

fn cmd_agent_sign(args: &[String]) -> Result<()> {
    let mut cred: Option<String> = None;
    let mut message = "easysign-linux test".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--message" => {
                message = args.get(i + 1).context("--message needs text")?.clone();
                i += 2;
            }
            "--cred" => {
                cred = Some(args.get(i + 1).context("--cred needs a value")?.clone());
                i += 2;
            }
            other => bail!("unexpected argument: {other}"),
        }
    }
    let credential_id = choose_credential(cred)?;
    let digest = Sha256::digest(message.as_bytes());

    let der = match agent_call(&ipc::Request::GetCert {
        credential_id: Some(credential_id.clone()),
    })? {
        ipc::Response::Cert(c) => c.der,
        ipc::Response::Error(e) => bail!("agent error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    };

    let sig = sign_via_agent(credential_id, digest.to_vec(), ipc::AlgoId::Sha256Rsa)?;

    println!(
        "signature ({} bytes) via agent: {}",
        sig.len(),
        base64::engine::general_purpose::STANDARD.encode(&sig)
    );
    std::fs::write("easysign-cert.pem", pem_cert(&der))?;
    std::fs::write("easysign-sig.bin", &sig)?;
    std::fs::write("easysign-msg.txt", &message)?;
    println!("\nverify with:");
    println!("  openssl x509 -in easysign-cert.pem -pubkey -noout > pub.pem");
    println!("  openssl dgst -sha256 -verify pub.pem -signature easysign-sig.bin easysign-msg.txt");
    Ok(())
}

/// Parse an optional positional credentialID plus one `--flag VALUE`.
fn parse_cred_and_flag(
    args: &[String],
    flag: &str,
    default: &str,
) -> Result<(Option<String>, String)> {
    let mut cred: Option<String> = None;
    let mut value = default.to_string();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            value = args
                .get(i + 1)
                .with_context(|| format!("{flag} needs a value"))?
                .clone();
            i += 2;
        } else {
            cred = Some(args[i].clone());
            i += 1;
        }
    }
    Ok((cred, value))
}

fn print_info(info: &CredentialInfo) {
    println!("credentialID: {}", info.credential_id);
    println!("SCAL:         {}", info.scal.as_deref().unwrap_or("?"));
    println!("authMode:     {}", info.auth_mode.as_deref().unwrap_or("?"));
    println!("key algos:    {}", info.key_algos.join(", "));
    println!("cert chain:   {} certificate(s)", info.cert_chain_der.len());
}

fn pem_cert(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
