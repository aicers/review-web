use anyhow::{anyhow, Result};

use super::AuthError;
use crate::Store;

/// Inserts a token into the store.
///
/// # Errors
///
/// Returns an error if the tokens in the store are invalid, if the token cannot be serialized, or
/// if the store cannot be accessed.
pub fn insert_token(store: &Store, token: &str, username: &str) -> Result<()> {
    store.access_token_map().insert(username, token)
}

/// Revokes a token from the store.
///
/// # Errors
///
/// Returns an error if the tokens in the store are invalid, if the token cannot be serialized, or
/// if the store cannot be accessed.
pub fn revoke_token(store: &Store, token: &str) -> Result<()> {
    let decoded_token = super::decode_token(token)?;
    let username = decoded_token.sub;
    store
        .access_token_map()
        .revoke(&username, token)
        .map_err(|_| anyhow!("The given token does not exist"))
}

pub(super) fn token_exists_in_store(
    store: &Store,
    token: &str,
    username: &str,
) -> Result<bool, AuthError> {
    store
        .access_token_map()
        .contains(username, token)
        .map_err(|_| AuthError::InvalidToken("Token not found in the database".into()))
}
