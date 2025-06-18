use std::collections::HashSet;

/// Username validation errors
///
/// # Errors
///
/// This enum represents various validation failures that can occur when
/// processing usernames.
#[derive(Debug, thiserror::Error)]
pub(super) enum UsernameValidationError {
    #[error("Username must be between 3 and 30 characters")]
    InvalidLength,
    #[error("Username must start with a lowercase English letter")]
    InvalidStart,
    #[error("Username contains invalid characters")]
    InvalidCharacters,
    #[error("Username contains consecutive special characters")]
    ConsecutiveSpecialChars,
    #[error("Username cannot end with special characters")]
    EndsWithSpecialChar,
    #[error("Username cannot contain whitespace")]
    ContainsWhitespace,
}

/// Validates a username according to the specified rules:
/// - Whitespace is not allowed
/// - Only lowercase English letters, digits, and three special characters (., -, _) are allowed
/// - Consecutive special characters and special characters at the end are not allowed
/// - The username must start with a lowercase English letter
/// - The length must be between 3 and 30 characters (inclusive)
///
/// Additionally, if uppercase letters are received, they are automatically converted to lowercase.
///
/// Returns the normalized (lowercase) username if valid.
///
/// # Errors
///
/// Returns an error if the username fails any validation rule:
/// - [`UsernameValidationError::ContainsWhitespace`] if the username contains whitespace characters
/// - [`UsernameValidationError::InvalidLength`] if the username is shorter than 3 or longer than 30 characters
/// - [`UsernameValidationError::InvalidStart`] if the username doesn't start with a lowercase English letter
/// - [`UsernameValidationError::InvalidCharacters`] if the username contains characters other than lowercase letters, digits, or the allowed special characters (., -, _)
/// - [`UsernameValidationError::ConsecutiveSpecialChars`] if the username contains consecutive special characters
/// - [`UsernameValidationError::EndsWithSpecialChar`] if the username ends with a special character
pub(super) fn validate_and_normalize_username(
    username: &str,
) -> Result<String, UsernameValidationError> {
    // Convert to lowercase first
    let normalized = username.to_lowercase();

    // Check for whitespace
    if normalized.contains(char::is_whitespace) {
        return Err(UsernameValidationError::ContainsWhitespace);
    }

    // Check length
    if normalized.len() < 3 || normalized.len() > 30 {
        return Err(UsernameValidationError::InvalidLength);
    }

    // Check if it starts with a lowercase English letter
    let chars: Vec<char> = normalized.chars().collect();
    if !chars.first().unwrap().is_ascii_lowercase() {
        return Err(UsernameValidationError::InvalidStart);
    }

    // Special characters allowed
    let special_chars: HashSet<char> = ['.', '-', '_'].into_iter().collect();

    // Check for valid characters only
    for ch in &chars {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && !special_chars.contains(ch) {
            return Err(UsernameValidationError::InvalidCharacters);
        }
    }

    // Check for consecutive special characters and ending with special characters
    let mut prev_was_special = false;
    for (i, ch) in chars.iter().enumerate() {
        let is_special = special_chars.contains(ch);

        // Check consecutive special characters
        if is_special && prev_was_special {
            return Err(UsernameValidationError::ConsecutiveSpecialChars);
        }

        // Check if username ends with special character
        if i == chars.len() - 1 && is_special {
            return Err(UsernameValidationError::EndsWithSpecialChar);
        }

        prev_was_special = is_special;
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        // Valid cases
        assert_eq!(validate_and_normalize_username("abc").unwrap(), "abc");
        assert_eq!(validate_and_normalize_username("user1").unwrap(), "user1");
        assert_eq!(
            validate_and_normalize_username("test.user").unwrap(),
            "test.user"
        );
        assert_eq!(
            validate_and_normalize_username("test-user").unwrap(),
            "test-user"
        );
        assert_eq!(
            validate_and_normalize_username("test_user").unwrap(),
            "test_user"
        );
        assert_eq!(
            validate_and_normalize_username("user123").unwrap(),
            "user123"
        );
        assert_eq!(validate_and_normalize_username("a1b2c3").unwrap(), "a1b2c3");

        // Uppercase conversion
        assert_eq!(validate_and_normalize_username("ABC").unwrap(), "abc");
        assert_eq!(validate_and_normalize_username("User1").unwrap(), "user1");
        assert_eq!(
            validate_and_normalize_username("Test.User").unwrap(),
            "test.user"
        );
    }

    #[test]
    fn test_invalid_length() {
        // Too short
        assert!(matches!(
            validate_and_normalize_username("ab"),
            Err(UsernameValidationError::InvalidLength)
        ));

        // Too long
        assert!(matches!(
            validate_and_normalize_username("a".repeat(31).as_str()),
            Err(UsernameValidationError::InvalidLength)
        ));
    }

    #[test]
    fn test_invalid_start() {
        // Starting with digit
        assert!(matches!(
            validate_and_normalize_username("1abc"),
            Err(UsernameValidationError::InvalidStart)
        ));

        // Starting with special character
        assert!(matches!(
            validate_and_normalize_username(".abc"),
            Err(UsernameValidationError::InvalidStart)
        ));
        assert!(matches!(
            validate_and_normalize_username("-abc"),
            Err(UsernameValidationError::InvalidStart)
        ));
        assert!(matches!(
            validate_and_normalize_username("_abc"),
            Err(UsernameValidationError::InvalidStart)
        ));
    }

    #[test]
    fn test_invalid_characters() {
        // Invalid special characters
        assert!(matches!(
            validate_and_normalize_username("abc@def"),
            Err(UsernameValidationError::InvalidCharacters)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc#def"),
            Err(UsernameValidationError::InvalidCharacters)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc$def"),
            Err(UsernameValidationError::InvalidCharacters)
        ));
    }

    #[test]
    fn test_consecutive_special_chars() {
        assert!(matches!(
            validate_and_normalize_username("abc..def"),
            Err(UsernameValidationError::ConsecutiveSpecialChars)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc--def"),
            Err(UsernameValidationError::ConsecutiveSpecialChars)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc__def"),
            Err(UsernameValidationError::ConsecutiveSpecialChars)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc.-def"),
            Err(UsernameValidationError::ConsecutiveSpecialChars)
        ));
    }

    #[test]
    fn test_ends_with_special_char() {
        assert!(matches!(
            validate_and_normalize_username("abc."),
            Err(UsernameValidationError::EndsWithSpecialChar)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc-"),
            Err(UsernameValidationError::EndsWithSpecialChar)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc_"),
            Err(UsernameValidationError::EndsWithSpecialChar)
        ));
    }

    #[test]
    fn test_contains_whitespace() {
        assert!(matches!(
            validate_and_normalize_username("abc def"),
            Err(UsernameValidationError::ContainsWhitespace)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc\tdef"),
            Err(UsernameValidationError::ContainsWhitespace)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc\ndef"),
            Err(UsernameValidationError::ContainsWhitespace)
        ));
        assert!(matches!(
            validate_and_normalize_username(" abc"),
            Err(UsernameValidationError::ContainsWhitespace)
        ));
        assert!(matches!(
            validate_and_normalize_username("abc "),
            Err(UsernameValidationError::ContainsWhitespace)
        ));
    }

    #[test]
    fn test_boundary_cases() {
        // Exactly 3 characters
        assert_eq!(validate_and_normalize_username("abc").unwrap(), "abc");

        // Exactly 30 characters
        let valid_30_chars = "a".repeat(29) + "b";
        assert_eq!(
            validate_and_normalize_username(&valid_30_chars).unwrap(),
            valid_30_chars
        );

        // Mixed valid cases
        assert_eq!(
            validate_and_normalize_username("a1.b2-c3_d4").unwrap(),
            "a1.b2-c3_d4"
        );
    }
}
