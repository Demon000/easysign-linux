use crate::algo::Algo;
use crate::error::{Error, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::time::Duration;

/// Trans Sped exposes two distinct cloud products behind EasySign:
/// - `MSign`: phone number + Alias, authorize with signature password (PIN) + OTP,
///   no login/token. Host `msign.transsped.ro/csc/v0/local/`.
/// - `CloudSignature`: email + password OAuth2 login (Bearer). Host
///   `services.cloudsignature.online/csc/v1/`. Not yet implemented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    MSign,
    CloudSignature,
}

pub struct Client {
    base: String,
    flavor: Flavor,
    http: ureq::Agent,
}

#[derive(Clone, Debug)]
pub struct CredentialInfo {
    pub credential_id: String,
    /// DER-encoded certificates, leaf first.
    pub cert_chain_der: Vec<Vec<u8>>,
    pub key_algos: Vec<String>,
    /// Sole Control Assurance Level ("1" or "2") if the provider reports it.
    pub scal: Option<String>,
    pub auth_mode: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Sad {
    pub sad: String,
    pub expires_in: Option<u64>,
}

impl Client {
    pub fn new(base_url: &str, flavor: Flavor) -> Self {
        let mut base = base_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let http = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        Client { base, flavor, http }
    }

    /// Trans Sped mSign (phone + Alias, PIN + OTP).
    pub fn msign() -> Self {
        Self::new("https://msign.transsped.ro/csc/v0/local/", Flavor::MSign)
    }

    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn post(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(&self.url(path))
            .set("Content-Type", "application/json")
            .send_json(body)?;
        let text = resp.into_string()?;
        if std::env::var("EASYSIGN_DEBUG").is_ok() {
            eprintln!("[debug] POST {path} -> {text}");
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// List the credential IDs (Aliases) bound to a phone number.
    pub fn credentials_list(&self, user_id: &str) -> Result<Vec<String>> {
        let v = self.post("credentials/list", json!({ "userID": user_id }))?;
        let ids = v
            .get("credentialIDs")
            .and_then(|x| x.as_array())
            .ok_or_else(|| Error::Unexpected(format!("list: no credentialIDs in {v}")))?;
        Ok(ids
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect())
    }

    pub fn credentials_info(&self, credential_id: &str) -> Result<CredentialInfo> {
        let v = self.post(
            "credentials/info",
            json!({ "credentialID": credential_id, "certInfo": "true" }),
        )?;
        let cert_chain_der = v
            .pointer("/cert/certificates")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .filter_map(decode_cert)
                    .collect()
            })
            .unwrap_or_default();
        let key_algos = v
            .pointer("/key/algo")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(CredentialInfo {
            credential_id: credential_id.to_string(),
            cert_chain_der,
            key_algos,
            scal: v
                .get("SCAL")
                .or_else(|| v.get("scal"))
                .and_then(|x| x.as_str())
                .map(String::from),
            auth_mode: v.get("authMode").and_then(|x| x.as_str()).map(String::from),
        })
    }

    /// Trigger the SMS OTP for a credential.
    pub fn send_otp(&self, credential_id: &str) -> Result<()> {
        self.post("credentials/sendOTP", json!({ "credentialID": credential_id }))?;
        Ok(())
    }

    /// Authorize signing. `pin` is the signature password; `otp` the SMS code.
    /// The SAD returned is bound to `hashes` (SCAL2). EasySign hardcodes
    /// `numSignatures` to 1; whether the server honors larger values is untested.
    pub fn authorize(
        &self,
        credential_id: &str,
        num_signatures: u32,
        hashes: &[String],
        pin: &str,
        otp: &str,
    ) -> Result<Sad> {
        let v = self.post(
            "credentials/authorize",
            json!({
                "credentialID": credential_id,
                "numSignatures": num_signatures.to_string(),
                "hash": hashes,
                "PIN": pin,
                "OTP": otp,
            }),
        )?;
        let sad = v
            .get("SAD")
            .and_then(|x| x.as_str())
            .ok_or_else(|| Error::Unexpected(format!("authorize: no SAD in {v}")))?;
        Ok(Sad {
            sad: sad.to_string(),
            expires_in: v.get("expiresIn").and_then(|x| x.as_u64()),
        })
    }

    pub fn sign_hash(
        &self,
        credential_id: &str,
        sad: &str,
        hashes: &[String],
        algo: Algo,
    ) -> Result<Vec<Vec<u8>>> {
        let v = self.post(
            "signatures/signHash",
            json!({
                "credentialID": credential_id,
                "signAlgo": algo.sign_algo,
                "hashAlgo": algo.hash_algo,
                "signAlgoParams": "",
                "SAD": sad,
                "hash": hashes,
            }),
        )?;
        let candidates: Vec<&str> = match v.get("signatures").and_then(|x| x.as_array()) {
            Some(arr) => arr.iter().filter_map(|s| s.as_str()).collect(),
            None => v
                .get("signature")
                .and_then(|x| x.as_str())
                .into_iter()
                .collect(),
        };
        let out: Vec<Vec<u8>> = candidates.iter().filter_map(|s| decode_b64_any(s)).collect();
        if out.is_empty() {
            return Err(Error::Unexpected(format!("signHash: no decodable signature in {v}")));
        }
        Ok(out)
    }
}

fn decode_b64_any(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(&s)
        .or_else(|_| STANDARD_NO_PAD.decode(&s))
        .or_else(|_| URL_SAFE.decode(&s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&s))
        .ok()
}

fn decode_cert(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.trim())
        .ok()
}
