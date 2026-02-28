#[cfg(feature = "auth-jwt")]
mod jwt;
#[cfg(feature = "auth-mtls")]
mod mtls;
#[cfg(feature = "auth-jwt")]
mod store;

#[cfg(all(test, feature = "auth-jwt", not(feature = "auth-mtls")))]
pub(crate) use jwt::ForceAimerTokenFailureGuard;
#[cfg(feature = "auth-mtls")]
pub use mtls::{MtlsAuthError, MtlsAuthenticator, MtlsIdentity, validate_context_jwt};
#[cfg(feature = "auth-jwt")]
pub use {
    jwt::{
        create_aimer_token, create_token, decode_token, update_jwt_expires_in, update_jwt_secret,
        validate_token,
    },
    store::{insert_token, revoke_token},
};

#[cfg(feature = "auth-jwt")]
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
