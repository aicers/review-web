#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    str::FromStr,
    sync::{LazyLock, RwLock},
};

use anyhow::anyhow;
use async_graphql::Result;
use chrono::{NaiveDateTime, TimeDelta};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use review_database as database;
use serde::{Deserialize, Serialize};
use simple_asn1::{ASN1Block, from_der};

use super::{AuthError, store::token_exists_in_store};
use crate::Store;

const AIMER_SUBJECT: &str = "aice-web";

static JWT_EXPIRES_IN: LazyLock<RwLock<u32>> = LazyLock::new(|| RwLock::new(3600));
static JWT_SECRET: LazyLock<RwLock<Vec<u8>>> = LazyLock::new(|| RwLock::new(vec![]));

#[cfg(test)]
static FORCE_AIMER_TOKEN_FAILURE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: i64,
}

impl Claims {
    fn new(sub: String, role: String, exp: i64) -> Self {
        Self { sub, role, exp }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AimerClaims {
    sub: String,
    iss: String,
    iat: i64,
    exp: i64,
}

fn normalize_rsa_der(secret: &[u8]) -> Vec<u8> {
    let extract_inner_key = |blocks: &[ASN1Block]| -> Option<Vec<u8>> {
        let mut stack: Vec<&ASN1Block> = blocks.iter().rev().collect();

        while let Some(block) = stack.pop() {
            match block {
                ASN1Block::Sequence(_, entries) => {
                    stack.extend(entries.iter().rev());
                }
                ASN1Block::BitString(_, _, value) | ASN1Block::OctetString(_, value) => {
                    return Some(value.clone());
                }
                _ => {}
            }
        }

        None
    };

    if let Ok(blocks) = from_der(secret)
        && let Some(inner) = extract_inner_key(&blocks)
    {
        return inner;
    }

    secret.to_vec()
}

#[cfg(test)]
pub(crate) fn set_force_aimer_token_failure(enabled: bool) {
    FORCE_AIMER_TOKEN_FAILURE.store(enabled, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) struct ForceAimerTokenFailureGuard;

#[cfg(test)]
impl ForceAimerTokenFailureGuard {
    pub(crate) fn new() -> Self {
        set_force_aimer_token_failure(true);
        Self
    }
}

#[cfg(test)]
impl Drop for ForceAimerTokenFailureGuard {
    fn drop(&mut self) {
        set_force_aimer_token_failure(false);
    }
}

/// Creates a JWT token with the given username and role.
///
/// # Errors
///
/// Returns an error if the JWT locks are poisoned or if the JWT secret cannot be read.
pub fn create_token(username: String, role: String) -> Result<(String, NaiveDateTime), AuthError> {
    let expires_in = *JWT_EXPIRES_IN
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let Some(delta) = TimeDelta::try_seconds(expires_in.into()) else {
        unreachable!("`JWT_EXPIRES_IN` is greather than 0 and less than 2^32")
    };
    let exp = chrono::Utc::now() + delta;

    let claims = Claims::new(username, role, exp.timestamp());
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret),
    )?;
    let expiration_time = NaiveDateTime::new(exp.date_naive(), exp.time());

    Ok((token, expiration_time))
}

/// Creates an Aimer-compatible JWT token with RS256 signing.
///
/// # Errors
///
/// Returns an error if the JWT locks are poisoned, if the JWT secret cannot be read,
/// or if the hostname cannot be determined.
pub fn create_aimer_token(exp: i64) -> Result<String, AuthError> {
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;

    #[cfg(test)]
    if FORCE_AIMER_TOKEN_FAILURE.load(Ordering::SeqCst) {
        return Err(AuthError::Other(
            "Forced Aimer token failure (test)".to_string(),
        ));
    }

    let hostname = roxy::hostname();
    if hostname.is_empty() {
        return Err(AuthError::Other(
            "Failed to obtain hostname for Aimer token".to_string(),
        ));
    }

    let iat = chrono::Utc::now().timestamp();
    let iss = format!("https://{hostname}");

    let claims = AimerClaims {
        sub: AIMER_SUBJECT.to_string(),
        iss,
        iat,
        exp,
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(hostname);

    let rsa_der = normalize_rsa_der(&jwt_secret);
    let token = encode(&header, &claims, &EncodingKey::from_rsa_der(&rsa_der))?;

    Ok(token)
}

/// Decodes a JWT token and returns the claims.
///
/// # Errors
///
/// Returns an error if the JWT lock is poisoned or if the JWT secret cannot be read.
pub fn decode_token(token: &str) -> anyhow::Result<Claims> {
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let mut validation = Validation::default();
    validation.validate_exp = false; // Disable expiration validation
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(&jwt_secret), &validation)?;
    Ok(token_data.claims)
}

/// Updates the JWT expiration time.
///
/// # Errors
///
/// Returns an error if the JWT lock is poisoned.
pub fn update_jwt_expires_in(new_expires_in: u32) -> anyhow::Result<()> {
    JWT_EXPIRES_IN
        .write()
        .map(|mut expires_in| {
            *expires_in = new_expires_in;
        })
        .map_err(|e| anyhow!("jwt_expires_in: {e}"))
}

/// Updates the JWT secret.
///
/// # Errors
///
/// Returns an error if the JWT lock is poisoned.
pub fn update_jwt_secret(new_secret: Vec<u8>) -> anyhow::Result<()> {
    JWT_SECRET
        .write()
        .map(|mut secret| {
            *secret = new_secret;
        })
        .map_err(|e| anyhow!("jwt_secret: {e}"))
}

/// Validates a JWT token and returns the username and role.
///
/// # Errors
///
/// Returns an error if the JWT lock is poisoned, if the JWT secret cannot be read, or if the token
/// data is invalid.
pub fn validate_token(store: &Store, token: &str) -> Result<(String, database::Role), AuthError> {
    let jwt_secret = JWT_SECRET
        .read()
        .map_err(|e| AuthError::ReadJwtSecret(e.to_string()))?;
    let decoded_token = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret),
        &Validation::default(),
    )?;

    if token_exists_in_store(store, token, &decoded_token.claims.sub)? {
        let role = database::Role::from_str(&decoded_token.claims.role)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok((decoded_token.claims.sub, role))
    } else {
        Err(AuthError::InvalidToken(
            "Token not found in the database".into(),
        ))
    }
}
