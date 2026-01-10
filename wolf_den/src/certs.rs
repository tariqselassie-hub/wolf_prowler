use crate::error::Result;

/// Generates a self-signed certificate and private key in PEM format.
///
/// # Arguments
/// * `subject_alt_names` - A list of subject alternative names (e.g., "localhost", "127.0.0.1").
///
/// # Errors
///
/// Returns an error if certificate generation fails.
pub fn generate_self_signed_cert(subject_alt_names: Vec<String>) -> Result<(String, String)> {
    // Generate a simple self-signed certificate using rcgen's helper
    // This is robust across versions and suffices for our dev dashboard
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;

    // CertifiedKey struct contains both the certificate and the signing key
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_generation() {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let (cert_pem, key_pem) = generate_self_signed_cert(subject_alt_names).unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_empty_san() {
        let subject_alt_names = vec![];
        let (cert_pem, _) = generate_self_signed_cert(subject_alt_names).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
