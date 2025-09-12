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

use super::{AuthError, store::token_exists_in_store};
use crate::Store;

static JWT_EXPIRES_IN: LazyLock<RwLock<u32>> = LazyLock::new(|| RwLock::new(3600));
static JWT_SECRET: LazyLock<RwLock<Vec<u8>>> = LazyLock::new(|| RwLock::new(vec![]));

// Account lockout and suspension global settings
static LOCKOUT_THRESHOLD: LazyLock<RwLock<u8>> = LazyLock::new(|| RwLock::new(5));
static LOCKOUT_DURATION_MINUTES: LazyLock<RwLock<u32>> = LazyLock::new(|| RwLock::new(30));
static SUSPENSION_THRESHOLD: LazyLock<RwLock<u8>> = LazyLock::new(|| RwLock::new(10));

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
        .map_err(|e| anyhow!("jwt_expires_in: {}", e))
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
        .map_err(|e| anyhow!("jwt_secret: {}", e))
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

/// Gets the current lockout threshold.
///
/// # Errors
///
/// Returns an error if the lockout threshold lock is poisoned.
pub fn get_lockout_threshold() -> anyhow::Result<u8> {
    LOCKOUT_THRESHOLD
        .read()
        .map(|threshold| *threshold)
        .map_err(|e| anyhow!("lockout_threshold: {}", e))
}

/// Updates the lockout threshold.
///
/// # Errors
///
/// Returns an error if the lockout threshold lock is poisoned.
pub fn update_lockout_threshold(new_threshold: u8) -> anyhow::Result<()> {
    LOCKOUT_THRESHOLD
        .write()
        .map(|mut threshold| {
            *threshold = new_threshold;
        })
        .map_err(|e| anyhow!("lockout_threshold: {}", e))
}

/// Gets the current lockout duration in minutes.
///
/// # Errors
///
/// Returns an error if the lockout duration lock is poisoned.
pub fn get_lockout_duration_minutes() -> anyhow::Result<u32> {
    LOCKOUT_DURATION_MINUTES
        .read()
        .map(|duration| *duration)
        .map_err(|e| anyhow!("lockout_duration_minutes: {}", e))
}

/// Updates the lockout duration in minutes.
///
/// # Errors
///
/// Returns an error if the lockout duration lock is poisoned.
pub fn update_lockout_duration_minutes(new_duration: u32) -> anyhow::Result<()> {
    LOCKOUT_DURATION_MINUTES
        .write()
        .map(|mut duration| {
            *duration = new_duration;
        })
        .map_err(|e| anyhow!("lockout_duration_minutes: {}", e))
}

/// Gets the current suspension threshold.
///
/// # Errors
///
/// Returns an error if the suspension threshold lock is poisoned.
pub fn get_suspension_threshold() -> anyhow::Result<u8> {
    SUSPENSION_THRESHOLD
        .read()
        .map(|threshold| *threshold)
        .map_err(|e| anyhow!("suspension_threshold: {}", e))
}

/// Updates the suspension threshold.
///
/// # Errors
///
/// Returns an error if the suspension threshold lock is poisoned.
pub fn update_suspension_threshold(new_threshold: u8) -> anyhow::Result<()> {
    SUSPENSION_THRESHOLD
        .write()
        .map(|mut threshold| {
            *threshold = new_threshold;
        })
        .map_err(|e| anyhow!("suspension_threshold: {}", e))
}
