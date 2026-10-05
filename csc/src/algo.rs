#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algo {
    pub sign_algo: &'static str,
    pub hash_algo: &'static str,
}

/// RSASSA-PKCS1-v1_5 with SHA-256; the hash sent is the SHA-256 digest.
pub const SHA256_RSA: Algo = Algo {
    sign_algo: "1.2.840.113549.1.1.11",
    hash_algo: "2.16.840.1.101.3.4.2.1",
};

/// RSASSA-PKCS1-v1_5 with SHA-512.
pub const SHA512_RSA: Algo = Algo {
    sign_algo: "1.2.840.113549.1.1.13",
    hash_algo: "2.16.840.1.101.3.4.2.3",
};

/// Raw RSA: the HSM applies PKCS#1 padding to the bytes as supplied, letting the
/// caller pass an already-built DigestInfo. Used when NSS pre-digests for CKM_RSA_PKCS.
/// The hashAlgo OID here is Trans Sped private (2706) meaning "none / pre-hashed".
pub const RAW_RSA: Algo = Algo {
    sign_algo: "1.2.840.113549.1.1.1",
    hash_algo: "1.3.6.1.4.1.2706.2.4.1.1",
};
