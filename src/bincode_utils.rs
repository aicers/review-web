//! Utility functions for bincode v2 serialization and deserialization.
//!
//! This module provides helper functions that wrap bincode v2's API to maintain
//! compatibility with the legacy bincode v1 behavior.

use serde::{Serialize, de::DeserializeOwned};

/// Serialize data using the legacy configuration that matches `bincode::serialize`.
pub fn encode_legacy<T: Serialize>(data: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(data, bincode::config::legacy())
}

/// Serialize data using the legacy configuration that matches `bincode::DefaultOptions::new()`.
pub fn encode_legacy_variant<T: Serialize>(
    data: &T,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(data, bincode::config::legacy().with_variable_int_encoding())
}

/// Deserialize data using the legacy configuration that matches `bincode::DefaultOptions::new()`.
pub fn decode_legacy_variant<T: DeserializeOwned>(
    data: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    let (result, _len) = bincode::serde::decode_from_slice(
        data,
        bincode::config::legacy().with_variable_int_encoding(),
    )?;
    Ok(result)
}
