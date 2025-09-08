mod jwt;
mod store;

pub use {
    jwt::{
        create_token, decode_token, get_lockout_duration_minutes, get_lockout_threshold,
        get_suspension_threshold, update_jwt_expires_in, update_jwt_secret,
        update_lockout_duration_minutes, update_lockout_threshold, update_suspension_threshold,
        validate_token,
    },
    store::{insert_token, revoke_token},
};

#[derive(Debug, thiserror::Error)]
#[allow(clippy::module_name_repetitions)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("JWT error: {0}")]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
    #[error("Failed to read JWT_SECRET: {0}")]
    ReadJwtSecret(String),
    #[error("{0}")]
    Other(String),
}
