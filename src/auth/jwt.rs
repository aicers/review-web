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
