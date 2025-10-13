use rustls_pki_types::{ServerName, UnixTime};
use std::{collections::HashMap, sync::RwLock};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error as TLSError, SignatureScheme,
};

#[derive(Debug, Clone, Copy)]
pub enum TlsType {
    Plain,
    NativeTls,
    Rustls,
}

lazy_static::lazy_static! {
    static ref URL_TLS_TYPE: RwLock<HashMap<String, TlsType>> = RwLock::new(HashMap::new());
}

// https://github.com/seanmonstar/reqwest/blob/fd61bc93e6f936454ce0b978c6f282f06eee9287/src/tls.rs#L608
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[inline]
pub fn is_plain(url: &str) -> bool {
    url.starts_with("ws://") || url.starts_with("http://")
}

// Extract domain from URL.
// e.g., "https://example.com/path" -> "example.com"
//       "https://example.com:8080/path" -> "example.com:8080"
// See the tests for more examples.
#[inline]
fn get_domain_from_url(url: &str) -> &str {
    // Remove scheme (e.g., http://, https://, ws://, wss://)
    let scheme_end = url.find("://").map(|pos| pos + 3).unwrap_or(0);
    let url2 = &url[scheme_end..];
    // If userinfo is present, domain is after last '@'
    let after_at = match url2.rfind('@') {
        Some(pos) => &url2[pos + 1..],
        None => url2,
    };
    // Find the end of domain (before '/' or '?')
    let domain_end = after_at.find(&['/', '?'][..]).unwrap_or(after_at.len());
    &after_at[..domain_end]
}

#[inline]
pub fn upsert_tls_type(url: &str, tls_type: TlsType) {
    if is_plain(url) {
        return;
    }

    let domain = get_domain_from_url(url);
    URL_TLS_TYPE
        .write()
        .unwrap()
        .insert(domain.to_string(), tls_type);
}

#[inline]
pub fn get_cached_tls_type(url: &str) -> Option<TlsType> {
    if is_plain(url) {
        return Some(TlsType::Plain);
    }
    let domain = get_domain_from_url(url);
    URL_TLS_TYPE.read().unwrap().get(domain).cloned()
}

#[inline]
pub fn reset_tls_type_cache() {
    URL_TLS_TYPE.write().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domain_from_url() {
        for (url, expected_domain) in vec![
            ("http://example.com", "example.com"),
            ("https://example.com", "example.com"),
            ("ws://example.com/path", "example.com"),
            ("wss://example.com:8080/path", "example.com:8080"),
            ("https://user:pass@example.com", "example.com"),
            ("https://example.com?query=param", "example.com"),
            ("https://example.com:8443?query=param", "example.com:8443"),
            ("ftp://example.com/resource", "example.com"), // ftp scheme
            ("example.com/path", "example.com"),           // no scheme
            ("example.com:8080/path", "example.com:8080"),
        ] {
            let domain = get_domain_from_url(url);
            assert_eq!(domain, expected_domain);
        }
    }
}
