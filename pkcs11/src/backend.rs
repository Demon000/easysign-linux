use crate::agent;
use ipc::AlgoId;
use native_pkcs11_traits::{
    Backend, Certificate, KeyAlgorithm, KeySearchOptions, PrivateKey, PublicKey, Result,
    SignatureAlgorithm,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::Arc;

// PKCS#1 v1.5 DigestInfo prefixes.
const SHA1_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const SHA256_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_PREFIX: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Map a PKCS#11 signature request to what the CSC server expects: either a bare
/// hash with a server-side signAlgo, or a pre-built DigestInfo signed raw.
fn payload_for(algorithm: &SignatureAlgorithm, data: &[u8]) -> Result<(AlgoId, Vec<u8>)> {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => Ok((AlgoId::Sha256Rsa, Sha256::digest(data).to_vec())),
        SignatureAlgorithm::RsaPkcs1v15Sha512 => Ok((AlgoId::Sha512Rsa, Sha512::digest(data).to_vec())),
        SignatureAlgorithm::RsaPkcs1v15Sha1 => {
            Ok((AlgoId::RawRsa, [SHA1_PREFIX, &Sha1::digest(data)].concat()))
        }
        SignatureAlgorithm::RsaPkcs1v15Sha384 => {
            Ok((AlgoId::RawRsa, [SHA384_PREFIX, &Sha384::digest(data)].concat()))
        }
        // CKM_RSA_PKCS: `data` is a DigestInfo. Route SHA-256/512 to the verified
        // server hash paths; sign anything else raw.
        SignatureAlgorithm::RsaPkcs1v15Raw => {
            if data.len() == SHA256_PREFIX.len() + 32 && data.starts_with(SHA256_PREFIX) {
                Ok((AlgoId::Sha256Rsa, data[SHA256_PREFIX.len()..].to_vec()))
            } else if data.len() == SHA512_PREFIX.len() + 64 && data.starts_with(SHA512_PREFIX) {
                Ok((AlgoId::Sha512Rsa, data[SHA512_PREFIX.len()..].to_vec()))
            } else {
                Ok((AlgoId::RawRsa, data.to_vec()))
            }
        }
        SignatureAlgorithm::RsaRaw => Ok((AlgoId::RawRsa, data.to_vec())),
        SignatureAlgorithm::Ecdsa | SignatureAlgorithm::RsaPss { .. } => {
            Err("unsupported signature algorithm (cloud key is RSA PKCS#1 v1.5 only)".into())
        }
    }
}

fn id_for(pkcs1_der: &[u8]) -> Vec<u8> {
    Sha1::digest(pkcs1_der).to_vec()
}

#[derive(Debug)]
struct EasyPublicKey {
    id: Vec<u8>,
    label: String,
    pkcs1_der: Vec<u8>,
}

impl PublicKey for EasyPublicKey {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        self.label.clone()
    }
    fn to_der(&self) -> Vec<u8> {
        self.pkcs1_der.clone()
    }
    fn verify(&self, _algorithm: &SignatureAlgorithm, _data: &[u8], _signature: &[u8]) -> Result<()> {
        Err("verify not supported".into())
    }
    fn delete(self: Box<Self>) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

struct EasyPrivateKey {
    id: Vec<u8>,
    label: String,
    credential_id: String,
}

impl PrivateKey for EasyPrivateKey {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        self.label.clone()
    }
    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        let (algo, payload) = payload_for(algorithm, data)?;
        agent::sign(&self.credential_id, payload, algo).map_err(|e| e.into())
    }
    fn delete(&self) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

#[derive(Debug)]
struct EasyCertificate {
    id: Vec<u8>,
    label: String,
    der: Vec<u8>,
    public_key: EasyPublicKey,
}

impl Certificate for EasyCertificate {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        self.label.clone()
    }
    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }
    fn public_key(&self) -> &dyn PublicKey {
        &self.public_key
    }
    fn delete(self: Box<Self>) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

struct Entry {
    id: Vec<u8>,
    label: String,
    der: Vec<u8>,
    pkcs1_der: Vec<u8>,
    /// `Some` for a signing cert (has a private key), `None` for a CA cert.
    credential_id: Option<String>,
}

/// Trans Sped CA chain, embedded so the token presents a complete chain and no
/// separate NSS import is needed. NSS picks whichever certs a given leaf needs.
const CA_PEMS: &[&str] = &[
    include_str!("../ca/TransSpedRootCAG3.crt"),
    include_str!("../ca/TransSpedMobileeIDASQCAG3.crt"),
    include_str!("../ca/TransSpedQCAG3.crt"),
    include_str!("../ca/TransSpedAdvancedeIDASCAG3.crt"),
];

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
}

fn entry_from_der(der: Vec<u8>, label: String, credential_id: Option<String>) -> Option<Entry> {
    let pkcs1_der = csc::rsa_public_key_pkcs1(&der)?;
    Some(Entry {
        id: id_for(&pkcs1_der),
        label,
        der,
        pkcs1_der,
        credential_id,
    })
}

fn ca_entries() -> Vec<Entry> {
    CA_PEMS
        .iter()
        .filter_map(|pem| {
            let der = pem_to_der(pem)?;
            let label = csc::subject_cn(&der).unwrap_or_else(|| "Trans Sped CA".into());
            entry_from_der(der, label, None)
        })
        .collect()
}

/// Signing certs from the agent plus the embedded CA chain.
fn entries() -> Vec<Entry> {
    let mut out = match agent::list_certs() {
        Ok(certs) => certs
            .into_iter()
            .filter_map(|c| {
                let label = c.label.unwrap_or_else(|| c.credential_id.clone());
                entry_from_der(c.der, label, Some(c.credential_id))
            })
            .collect(),
        Err(e) => {
            eprintln!("easysign-pkcs11: {e}");
            Vec::new()
        }
    };
    out.extend(ca_entries());
    out
}

pub struct EasySignBackend;

impl EasySignBackend {
    fn matches(e: &Entry, q: &KeySearchOptions) -> bool {
        match q {
            KeySearchOptions::Id(id) => &e.id == id,
            KeySearchOptions::Label(label) => &e.label == label,
        }
    }

    fn private_key(e: &Entry) -> Arc<dyn PrivateKey> {
        Arc::new(EasyPrivateKey {
            id: e.id.clone(),
            label: e.label.clone(),
            credential_id: e
                .credential_id
                .clone()
                .expect("private_key only for signing certs"),
        })
    }

    fn public_key(e: &Entry) -> Box<dyn PublicKey> {
        Box::new(EasyPublicKey {
            id: e.id.clone(),
            label: e.label.clone(),
            pkcs1_der: e.pkcs1_der.clone(),
        })
    }
}

impl Backend for EasySignBackend {
    fn name(&self) -> String {
        "easysign".into()
    }

    fn find_all_certificates(&self) -> Result<Vec<Box<dyn Certificate>>> {
        Ok(entries()
            .into_iter()
            .map(|e| {
                Box::new(EasyCertificate {
                    id: e.id.clone(),
                    label: e.label.clone(),
                    der: e.der,
                    public_key: EasyPublicKey {
                        id: e.id,
                        label: e.label,
                        pkcs1_der: e.pkcs1_der,
                    },
                }) as Box<dyn Certificate>
            })
            .collect())
    }

    fn find_private_key(&self, query: KeySearchOptions) -> Result<Option<Arc<dyn PrivateKey>>> {
        Ok(entries()
            .iter()
            .find(|e| e.credential_id.is_some() && Self::matches(e, &query))
            .map(Self::private_key))
    }

    fn find_public_key(&self, query: KeySearchOptions) -> Result<Option<Box<dyn PublicKey>>> {
        Ok(entries()
            .iter()
            .find(|e| Self::matches(e, &query))
            .map(Self::public_key))
    }

    fn find_all_private_keys(&self) -> Result<Vec<Arc<dyn PrivateKey>>> {
        Ok(entries()
            .iter()
            .filter(|e| e.credential_id.is_some())
            .map(Self::private_key)
            .collect())
    }

    fn find_all_public_keys(&self) -> Result<Vec<Arc<dyn PublicKey>>> {
        Ok(entries()
            .iter()
            .map(|e| Arc::from(Self::public_key(e)))
            .collect())
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _label: Option<&str>,
    ) -> Result<Arc<dyn PrivateKey>> {
        Err("key generation not supported".into())
    }
}
