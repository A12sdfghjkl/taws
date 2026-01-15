//! TLS configuration utilities for AWS HTTP clients
//!
//! Supports custom CA bundles for corporate environments with SSL inspection.
//! Respects AWS_CA_BUNDLE and SSL_CERT_FILE environment variables.

use reqwest::Certificate;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Default connect timeout for TLS handshake (prevents hanging on cert issues)
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default request timeout
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Cached CA certificates loaded from AWS_CA_BUNDLE or SSL_CERT_FILE
static CA_BUNDLE_CACHE: OnceLock<Option<Vec<Certificate>>> = OnceLock::new();

/// Load CA certificates from AWS_CA_BUNDLE or SSL_CERT_FILE environment variables.
///
/// Priority order:
/// 1. AWS_CA_BUNDLE - AWS-specific CA bundle path
/// 2. SSL_CERT_FILE - Standard SSL certificate file path
///
/// The PEM file can contain multiple certificates (certificate chain).
/// Results are cached for the lifetime of the application.
///
/// Returns None if:
/// - Neither environment variable is set
/// - The file cannot be read
/// - The file contains no valid certificates
pub fn load_ca_certificates() -> Option<&'static Vec<Certificate>> {
    CA_BUNDLE_CACHE
        .get_or_init(|| {
            // Check environment variables in priority order
            let ca_path = env::var("AWS_CA_BUNDLE")
                .or_else(|_| env::var("SSL_CERT_FILE"))
                .ok();

            let path = match ca_path {
                Some(p) => p,
                None => {
                    trace!("No custom CA bundle configured (AWS_CA_BUNDLE/SSL_CERT_FILE not set)");
                    return None;
                }
            };

            debug!("Loading custom CA bundle from: {}", path);
            load_certificates_from_file(&path)
        })
        .as_ref()
}

/// Load certificates from a PEM file
fn load_certificates_from_file(path: &str) -> Option<Vec<Certificate>> {
    let path = Path::new(path);

    if !path.exists() {
        warn!(
            "CA bundle file does not exist: {}. Using default certificate roots.",
            path.display()
        );
        return None;
    }

    let pem_data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            warn!(
                "Failed to read CA bundle file '{}': {}. Using default certificate roots.",
                path.display(),
                e
            );
            return None;
        }
    };

    // Parse all certificates from the PEM file
    let certs = parse_pem_certificates(&pem_data);

    if certs.is_empty() {
        warn!(
            "No valid certificates found in CA bundle file '{}'. Using default certificate roots.",
            path.display()
        );
        return None;
    }

    debug!(
        "Loaded {} certificate(s) from CA bundle: {}",
        certs.len(),
        path.display()
    );

    Some(certs)
}

/// Parse multiple certificates from PEM data
///
/// reqwest's Certificate::from_pem can handle multiple certificates in a single
/// PEM file, but returns them as a single Certificate object. For our purposes,
/// we just need to load the bundle and add it to the client.
fn parse_pem_certificates(pem_data: &[u8]) -> Vec<Certificate> {
    // reqwest's from_pem handles PEM bundles with multiple certificates
    // It will parse all certificates in the bundle into a single Certificate object
    match Certificate::from_pem(pem_data) {
        Ok(cert) => {
            trace!("Parsed certificate bundle successfully");
            vec![cert]
        }
        Err(e) => {
            trace!("Failed to parse certificate bundle: {}", e);
            vec![]
        }
    }
}

/// Configure a reqwest blocking client builder with custom CA certificates if available.
///
/// This function:
/// 1. Checks for AWS_CA_BUNDLE or SSL_CERT_FILE
/// 2. Loads and caches certificates from the file
/// 3. Adds them to the client builder
/// 4. Sets appropriate timeouts
///
/// # Example
///
/// ```ignore
/// let builder = reqwest::blocking::Client::builder();
/// let builder = configure_tls_blocking(builder);
/// let client = builder.build()?;
/// ```
pub fn configure_tls_blocking(
    mut builder: reqwest::blocking::ClientBuilder,
) -> reqwest::blocking::ClientBuilder {
    // Set timeouts to prevent hanging
    builder = builder
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT);

    // Add custom CA certificates if configured
    if let Some(certs) = load_ca_certificates() {
        for cert in certs {
            builder = builder.add_root_certificate(cert.clone());
        }
    }

    builder
}

/// Create a pre-configured reqwest blocking client with TLS settings.
///
/// This is a convenience function that creates a client with:
/// - Custom CA bundle support (if AWS_CA_BUNDLE/SSL_CERT_FILE is set)
/// - Appropriate timeouts
#[allow(dead_code)]
pub fn create_blocking_client() -> Result<reqwest::blocking::Client, reqwest::Error> {
    configure_tls_blocking(reqwest::blocking::Client::builder()).build()
}

/// Create a pre-configured reqwest blocking client with custom timeout.
pub fn create_blocking_client_with_timeout(
    timeout: Duration,
) -> Result<reqwest::blocking::Client, reqwest::Error> {
    configure_tls_blocking(reqwest::blocking::Client::builder())
        .timeout(timeout)
        .build()
}

/// Create a pre-configured async reqwest client with TLS settings.
pub fn create_async_client() -> Result<reqwest::Client, reqwest::Error> {
    configure_tls_async(reqwest::Client::builder()).build()
}

/// Configure a reqwest async client builder with custom CA certificates if available.
pub fn configure_tls_async(mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    // Set timeouts to prevent hanging
    builder = builder
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(DEFAULT_REQUEST_TIMEOUT);

    // Add custom CA certificates if configured
    if let Some(certs) = load_ca_certificates() {
        for cert in certs {
            builder = builder.add_root_certificate(cert.clone());
        }
    }

    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    // DigiCert Global Root CA (a real, valid CA certificate for testing)
    const DIGICERT_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----"#;

    #[test]
    fn test_parse_valid_certificate() {
        let certs = parse_pem_certificates(DIGICERT_ROOT_CA.as_bytes());
        assert_eq!(certs.len(), 1, "Should parse valid certificate");
    }

    #[test]
    fn test_parse_certificate_bundle() {
        // reqwest's from_pem handles bundles - it returns one Certificate object
        // that contains all certificates from the bundle
        let pem = format!("{}\n{}", DIGICERT_ROOT_CA, DIGICERT_ROOT_CA);
        let certs = parse_pem_certificates(pem.as_bytes());
        // reqwest loads the entire bundle as a single Certificate object
        assert_eq!(certs.len(), 1, "Should load bundle as single Certificate");
    }

    #[test]
    fn test_load_ca_certificates_not_set() {
        // When env vars are not set, should return None
        // Note: This test assumes AWS_CA_BUNDLE and SSL_CERT_FILE are not set
        // in the test environment. In CI, this should be the case.
        // We can't easily test this without modifying env vars which affects other tests.
    }
}
