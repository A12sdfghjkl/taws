//! AWS Client - Lightweight HTTP-based client
//!
//! Uses SigV4 signing with direct HTTP calls instead of heavy SDK

use anyhow::Result;

use super::credentials::load_credentials;
use super::http::AwsHttpClient;

/// Container for AWS HTTP client
pub struct AwsClients {
    pub http: AwsHttpClient,
    pub region: String,
    pub profile: String,
}

impl AwsClients {
    /// Create AWS client for a given profile and region
    pub async fn new(profile: &str, region: &str, endpoint_url: Option<String>) -> Result<(Self, String)> {
        let credentials = load_credentials(profile)?;
        let http = AwsHttpClient::new(credentials, region, endpoint_url);

        let client = Self {
            http,
            region: region.to_string(),
            profile: profile.to_string(),
        };

        Ok((client, region.to_string()))
    }

    /// Recreate client for a new region (keeps same profile)
    pub async fn switch_region(&mut self, profile: &str, region: &str) -> Result<String> {
        let credentials = load_credentials(profile)?;
        self.http.set_credentials(credentials);
        self.http.set_region(region);
        self.region = region.to_string();
        self.profile = profile.to_string();
        Ok(region.to_string())
    }
}

/// Format AWS errors into user-friendly messages
pub fn format_aws_error(err: &anyhow::Error) -> String {
    let err_str = err.to_string();
    
    // Check for common AWS error patterns
    if err_str.contains("dispatch failure") || err_str.contains("connection") {
        return "Connection failed - check internet/credentials".to_string();
    }
    if err_str.contains("InvalidClientTokenId") || err_str.contains("SignatureDoesNotMatch") {
        return "Invalid credentials - run 'aws configure'".to_string();
    }
    if err_str.contains("ExpiredToken") {
        return "Credentials expired - refresh or reconfigure".to_string();
    }
    if err_str.contains("AccessDenied") || err_str.contains("UnauthorizedAccess") {
        return "Access denied - check IAM permissions".to_string();
    }
    if err_str.contains("No credentials") || err_str.contains("no credentials") {
        return "No credentials - run 'aws configure'".to_string();
    }
    if err_str.contains("timeout") || err_str.contains("Timeout") {
        return "Request timed out - check connection".to_string();
    }
    if err_str.contains("region") {
        return "Region error - check AWS_REGION".to_string();
    }
    
    // Default: truncate long errors
    if err_str.len() > 60 {
        format!("{}...", &err_str[..60])
    } else {
        err_str
    }
}
