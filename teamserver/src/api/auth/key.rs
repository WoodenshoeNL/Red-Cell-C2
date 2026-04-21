//! API key extraction helpers.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::ApiAuthError;

pub(crate) const API_KEY_HEADER: &str = "x-api-key";
pub(super) const BEARER_PREFIX: &str = "Bearer ";
pub(super) const API_KEY_HASH_SECRET_SIZE: usize = 32;

pub(super) type ApiKeyMac = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ApiKeyDigest(pub(super) [u8; 32]);

pub(super) fn hash_api_key(secret: &[u8; API_KEY_HASH_SECRET_SIZE], api_key: &str) -> ApiKeyDigest {
    let mut mac = ApiKeyMac::new_from_slice(secret)
        .unwrap_or_else(|_| unreachable!("hmac accepts arbitrary secret lengths"));
    mac.update(api_key.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    ApiKeyDigest(bytes)
}

pub(super) fn generate_key_hash_secret() -> Result<[u8; API_KEY_HASH_SECRET_SIZE], getrandom::Error>
{
    let mut bytes = [0_u8; API_KEY_HASH_SECRET_SIZE];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Extract API key from request headers (X-API-Key or Bearer token).
pub(crate) fn extract_api_key(headers: &HeaderMap) -> Result<String, ApiAuthError> {
    if let Some(value) = headers.get(API_KEY_HEADER) {
        let key = value.to_str().map_err(|_| ApiAuthError::InvalidAuthorizationHeader)?;
        if key.trim().is_empty() {
            return Err(ApiAuthError::MissingApiKey);
        }

        return Ok(key.to_owned());
    }

    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(ApiAuthError::MissingApiKey);
    };
    let value = value.to_str().map_err(|_| ApiAuthError::InvalidAuthorizationHeader)?;
    let Some(token) = value.strip_prefix(BEARER_PREFIX) else {
        return Err(ApiAuthError::InvalidAuthorizationHeader);
    };

    if token.trim().is_empty() {
        return Err(ApiAuthError::MissingApiKey);
    }

    Ok(token.to_owned())
}
