use der::Decode;
use x509_cert::Certificate;

/// The certificate subject as an RFC 4514 string (e.g. "CN=...,C=RO").
pub fn subject_string(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    Some(cert.tbs_certificate.subject.to_string())
}

/// The Common Name (CN) from the subject, if present.
pub fn subject_cn(der: &[u8]) -> Option<String> {
    cn_from_subject(&subject_string(der)?)
}

/// A human-readable label for a certificate: CN (or full subject) plus expiry,
/// e.g. "COSMIN-GABRIEL TANISLAV (expires 2029-08-11)".
pub fn describe(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    let subject = cert.tbs_certificate.subject.to_string();
    let who = cn_from_subject(&subject).unwrap_or(subject);
    let na = cert.tbs_certificate.validity.not_after.to_date_time();
    Some(format!(
        "{who} (expires {:04}-{:02}-{:02})",
        na.year(),
        na.month(),
        na.day()
    ))
}

/// The RSA public key as PKCS#1 `RSAPublicKey` DER (the SPKI subjectPublicKey
/// bytes), which is what PKCS#11 consumers parse for CKA_MODULUS / CKA_PUBLIC_EXPONENT.
pub fn rsa_public_key_pkcs1(der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(der).ok()?;
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(|b| b.to_vec())
}

fn cn_from_subject(subject: &str) -> Option<String> {
    subject
        .split(',')
        .map(str::trim)
        .find_map(|rdn| rdn.strip_prefix("CN=").map(str::to_string))
}
