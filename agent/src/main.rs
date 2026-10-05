mod config;

use anyhow::{bail, Context, Result};
use base64::Engine;
use config::ProfileConfig;
use csc::{algo, Algo, Client};
use ipc::{AlgoId, CertEntry, ProfileInfo, Request, Response};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

/// How long a produced signature is reusable. RSA PKCS#1 v1.5 is deterministic, so
/// the same (algo, hash) always yields the same bytes; caching it lets the PKCS#11
/// length-query + real call (two C_Sign calls) cost a single OTP.
const SIG_TTL: Duration = Duration::from_secs(300);

fn algo_key(a: AlgoId) -> u8 {
    match a {
        AlgoId::Sha256Rsa => 1,
        AlgoId::Sha512Rsa => 2,
        AlgoId::RawRsa => 3,
    }
}

/// One certificate exposed by the agent, with its own credential auth state.
struct CertState {
    account: String,
    credential_id: String,
    label: Option<String>,
    cert_chain: Vec<Vec<u8>>,
    password: Option<String>,
    sig_cache: HashMap<(u8, Vec<u8>), (Vec<u8>, Instant)>,
}

struct Account {
    name: String,
    user_id: String,
}

struct Agent {
    client: Client,
    accounts: Vec<Account>,
    certs: Vec<CertState>,
}

/// Fetch every certificate bound to an account's phone number.
fn load_account(client: &Client, cfg: &ProfileConfig) -> Result<Vec<CertState>> {
    let ids = client.credentials_list(&cfg.user_id)?;
    if ids.is_empty() {
        bail!("no credentials for {}", cfg.user_id);
    }
    let mut certs = Vec::new();
    for credential_id in ids {
        let info = client.credentials_info(&credential_id)?;
        let Some(leaf) = info.cert_chain_der.first() else {
            eprintln!("easysign-agent: {credential_id} has no certificate, skipping");
            continue;
        };
        certs.push(CertState {
            account: cfg.name.clone(),
            label: csc::describe(leaf),
            credential_id,
            cert_chain: info.cert_chain_der,
            password: None,
            sig_cache: HashMap::new(),
        });
    }
    Ok(certs)
}

fn map_algo(algo_id: AlgoId) -> Algo {
    match algo_id {
        AlgoId::Sha256Rsa => algo::SHA256_RSA,
        AlgoId::Sha512Rsa => algo::SHA512_RSA,
        AlgoId::RawRsa => algo::RAW_RSA,
    }
}

fn first_sig(sigs: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    sigs.into_iter()
        .next()
        .context("signHash returned no signature")
}

/// Drive a `Sign` request: reuse a cached SAD if possible, otherwise send the OTP,
/// ask the client (over the same connection) for the password/OTP, authorize, and
/// sign. All responses are written to `writer`.
fn do_sign<R: BufRead, W: Write>(
    client: &Client,
    cert: &mut CertState,
    hash: &[u8],
    algo_id: AlgoId,
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let algo = map_algo(algo_id);
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    let cache_key = (algo_key(algo_id), hash.to_vec());

    // Fast path: this exact (algo, hash) was just signed. RSA PKCS#1 v1.5 is
    // deterministic, so returning the cached bytes is identical to re-signing and
    // avoids a second OTP on the PKCS#11 length-query call.
    if let Some((sig, when)) = cert.sig_cache.get(&cache_key) {
        if when.elapsed() < SIG_TTL {
            ipc::write_msg(writer, &Response::Signature(sig.clone()))?;
            return Ok(());
        }
    }

    // Need a new SAD. Send the OTP, then ask the client for credentials.
    if let Err(e) = client.send_otp(&cert.credential_id) {
        ipc::write_msg(writer, &Response::Error(format!("{:#}", anyhow::Error::new(e))))?;
        return Ok(());
    }
    let label = cert.label.clone().unwrap_or_else(|| cert.credential_id.clone());
    ipc::write_msg(
        writer,
        &Response::NeedCredentials {
            ask_password: cert.password.is_none(),
            label,
        },
    )?;

    let (password, otp) = match ipc::read_msg::<_, Request>(reader)? {
        Some(Request::Credentials { password, otp }) => (password, otp),
        Some(_) => {
            ipc::write_msg(writer, &Response::Error("expected Credentials".into()))?;
            return Ok(());
        }
        None => return Ok(()), // client hung up
    };
    if let Some(p) = password {
        cert.password = Some(p);
    }
    let pin = match &cert.password {
        Some(p) => p.clone(),
        None => {
            ipc::write_msg(writer, &Response::Error("no password provided".into()))?;
            return Ok(());
        }
    };

    let sad = match client.authorize(&cert.credential_id, 1, &[hash_b64.clone()], &pin, &otp) {
        Ok(s) => s,
        Err(e) => {
            cert.password = None; // wrong PIN/OTP: re-prompt next time
            ipc::write_msg(
                writer,
                &Response::Error(format!("authorize failed: {:#}", anyhow::Error::new(e))),
            )?;
            return Ok(());
        }
    };
    match client.sign_hash(&cert.credential_id, &sad.sad, &[hash_b64], algo) {
        Ok(s) => {
            let sig = first_sig(s)?;
            cert.sig_cache.insert(cache_key, (sig.clone(), Instant::now()));
            ipc::write_msg(writer, &Response::Signature(sig))?;
        }
        Err(e) => ipc::write_msg(writer, &Response::Error(format!("{:#}", anyhow::Error::new(e))))?,
    }
    Ok(())
}

impl Agent {
    fn new(configs: &[ProfileConfig]) -> Self {
        let client = Client::msign();
        let mut accounts = Vec::new();
        let mut certs = Vec::new();
        for cfg in configs {
            match load_account(&client, cfg) {
                Ok(mut cs) => {
                    eprintln!(
                        "easysign-agent: account '{}' ({}): {} cert(s)",
                        cfg.name,
                        cfg.user_id,
                        cs.len()
                    );
                    accounts.push(Account {
                        name: cfg.name.clone(),
                        user_id: cfg.user_id.clone(),
                    });
                    certs.append(&mut cs);
                }
                Err(e) => eprintln!("easysign-agent: skipping account '{}': {e}", cfg.name),
            }
        }
        Agent {
            client,
            accounts,
            certs,
        }
    }

    fn index_of(&self, credential_id: &Option<String>) -> Result<usize> {
        match credential_id {
            Some(id) => self
                .certs
                .iter()
                .position(|c| &c.credential_id == id)
                .with_context(|| format!("no certificate with credentialID {id}")),
            None => match self.certs.len() {
                0 => bail!("no certificates; run: easysign profile add <phone>"),
                1 => Ok(0),
                _ => bail!("multiple certificates; specify a credentialID"),
            },
        }
    }

    fn as_config(&self) -> Vec<ProfileConfig> {
        self.accounts
            .iter()
            .map(|a| ProfileConfig {
                name: a.name.clone(),
                user_id: a.user_id.clone(),
            })
            .collect()
    }

    fn add_account(&mut self, name: Option<String>, user_id: String, persist: bool) -> Result<()> {
        // Reuse the name of an existing account on the same phone, else pick one.
        let name = name.unwrap_or_else(|| {
            if let Some(a) = self.accounts.iter().find(|a| a.user_id == user_id) {
                a.name.clone()
            } else if self.accounts.is_empty() {
                "default".into()
            } else {
                let mut i = self.accounts.len() + 1;
                loop {
                    let cand = format!("account{i}");
                    if !self.accounts.iter().any(|a| a.name == cand) {
                        break cand;
                    }
                    i += 1;
                }
            }
        });
        let cfg = ProfileConfig {
            name: name.clone(),
            user_id: user_id.clone(),
        };
        let certs = load_account(&self.client, &cfg)?;
        // Replace any prior state for this account.
        self.certs.retain(|c| c.account != name);
        self.accounts.retain(|a| a.name != name);
        self.accounts.push(Account { name, user_id });
        self.certs.extend(certs);
        if persist {
            config::save(&self.as_config())?;
        }
        Ok(())
    }

    fn profile_infos(&self) -> Vec<ProfileInfo> {
        self.accounts
            .iter()
            .map(|a| ProfileInfo {
                name: a.name.clone(),
                user_id: a.user_id.clone(),
                num_certs: self.certs.iter().filter(|c| c.account == a.name).count(),
            })
            .collect()
    }

    fn cert_entries(&self) -> Vec<CertEntry> {
        self.certs
            .iter()
            .map(|c| CertEntry {
                credential_id: c.credential_id.clone(),
                account: c.account.clone(),
                label: c.label.clone(),
                der: c.cert_chain[0].clone(),
            })
            .collect()
    }

    fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::ListProfiles => Response::Profiles(self.profile_infos()),
            Request::AddProfile {
                name,
                user_id,
                persist,
            } => match self.add_account(name, user_id, persist) {
                Ok(()) => Response::Profiles(self.profile_infos()),
                Err(e) => Response::Error(format!("{e:#}")),
            },
            Request::RemoveProfile { name } => {
                let before = self.accounts.len();
                self.accounts.retain(|a| a.name != name);
                self.certs.retain(|c| c.account != name);
                if self.accounts.len() == before {
                    return Response::Error(format!("no account named {name}"));
                }
                if let Err(e) = config::save(&self.as_config()) {
                    return Response::Error(format!("{e:#}"));
                }
                Response::Ok
            }
            Request::ListCerts => Response::Certs(self.cert_entries()),
            Request::GetCert { credential_id } => match self.index_of(&credential_id) {
                Ok(i) => Response::Cert(CertEntry {
                    credential_id: self.certs[i].credential_id.clone(),
                    account: self.certs[i].account.clone(),
                    label: self.certs[i].label.clone(),
                    der: self.certs[i].cert_chain[0].clone(),
                }),
                Err(e) => Response::Error(format!("{e:#}")),
            },
            // Sign is interactive and handled in handle_conn.
            Request::Sign { .. } | Request::Credentials { .. } => {
                Response::Error("protocol error".into())
            }
            Request::Logout { name } => {
                for c in self.certs.iter_mut() {
                    if name.as_ref().map_or(true, |n| n == &c.account) {
                        c.password = None;
                        c.sig_cache.clear();
                    }
                }
                Response::Ok
            }
        }
    }
}

fn handle_conn(agent: &mut Agent, stream: UnixStream) -> Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    while let Some(req) = ipc::read_msg::<_, Request>(&mut reader)? {
        match req {
            Request::Sign {
                credential_id,
                hash,
                algo,
            } => match agent.index_of(&credential_id) {
                Ok(i) => {
                    let client = &agent.client;
                    let cert = &mut agent.certs[i];
                    do_sign(client, cert, &hash, algo, &mut reader, &mut writer)?;
                }
                Err(e) => ipc::write_msg(&mut writer, &Response::Error(format!("{e:#}")))?,
            },
            other => {
                let resp = agent.handle(other);
                ipc::write_msg(&mut writer, &resp)?;
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut agent = Agent::new(&config::load());

    let path = ipc::socket_path();
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    eprintln!(
        "easysign-agent: listening on {} ({} cert(s))",
        path.display(),
        agent.certs.len()
    );

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_conn(&mut agent, stream) {
                    eprintln!("easysign-agent: connection error: {e}");
                }
            }
            Err(e) => eprintln!("easysign-agent: accept error: {e}"),
        }
    }
    Ok(())
}
