//! Bincode v2 compatibility utilities.
//!
//! This module provides wrapper functions for bincode serialization that
//! maintain compatibility with bincode v1 semantics using the legacy config.

use serde::{Serialize, de::DeserializeOwned};

/// Serializes a value using bincode with legacy (v1) compatibility settings.
///
/// # Errors
///
/// Returns an error if the value cannot be serialized.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

/// Deserializes a value using bincode with legacy (v1) compatibility settings.
///
/// # Errors
///
/// Returns an error if the bytes cannot be deserialized into the target type.
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError> {
    let (value, _): (T, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        id: u32,
        name: String,
        values: Vec<i64>,
    }

    #[test]
    fn roundtrip_simple_struct() {
        let original = TestStruct {
            id: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3],
        };

        let encoded = serialize(&original).expect("serialization should succeed");
        let decoded: TestStruct = deserialize(&encoded).expect("deserialization should succeed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_tuple() {
        let original = (vec![1u8, 2, 3], vec![4u8, 5, 6]);

        let encoded = serialize(&original).expect("serialization should succeed");
        let decoded: (Vec<u8>, Vec<u8>) =
            deserialize(&encoded).expect("deserialization should succeed");

        assert_eq!(original, decoded);
    }
}
