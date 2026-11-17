//! The GraphQL `DateTime` scalar for `jiff::Timestamp` fields.
//!
//! This type exists only because async-graphql does not support jiff 1 yet;
//! it parses and prints exactly what async-graphql's built-in jiff scalar
//! does. Once async-graphql supports jiff 1, the body of this module is
//! replaced by `pub use jiff::Timestamp;`.

use std::{fmt, ops::Deref};

use async_graphql::{InputValueError, InputValueResult, Scalar, ScalarType, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

#[Scalar(
    name = "DateTime",
    specified_by_url = "https://datatracker.ietf.org/doc/html/rfc3339"
)]
impl ScalarType for Timestamp {
    fn parse(value: Value) -> InputValueResult<Self> {
        match value {
            Value::String(s) => Ok(Self(s.parse()?)),
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.0.to_string())
    }
}

impl From<jiff::Timestamp> for Timestamp {
    fn from(ts: jiff::Timestamp) -> Self {
        Self(ts)
    }
}

impl From<Timestamp> for jiff::Timestamp {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

impl Deref for Timestamp {
    type Target = jiff::Timestamp;

    fn deref(&self) -> &jiff::Timestamp {
        &self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
#[allow(
    clippy::useless_conversion,
    reason = "identity conversions while `Timestamp` re-exports `jiff::Timestamp`; real ones with the newtype"
)]
mod tests {
    use async_graphql::{ScalarType, Value};

    use super::Timestamp;

    const SECOND: i64 = 1_773_586_804; // 2026-03-15T15:00:04Z

    fn at(nanosecond: i32) -> Timestamp {
        Timestamp::from(jiff::Timestamp::new(SECOND, nanosecond).expect("valid timestamp"))
    }

    #[test]
    fn output_matches_rfc3339_with_trimmed_fraction() {
        for (nanosecond, expected) in [
            (0, "2026-03-15T15:00:04Z"),
            (123_000_000, "2026-03-15T15:00:04.123Z"),
            (123_456_000, "2026-03-15T15:00:04.123456Z"),
            (123_456_789, "2026-03-15T15:00:04.123456789Z"),
            (120_000_000, "2026-03-15T15:00:04.12Z"),
        ] {
            assert_eq!(
                <Timestamp as ScalarType>::to_value(&at(nanosecond)),
                Value::String(expected.to_owned())
            );
        }
    }

    #[test]
    fn input_accepts_any_offset() {
        let expected = jiff::Timestamp::new(SECOND, 0).expect("valid timestamp");
        for input in [
            "2026-03-15T15:00:04Z",
            "2026-03-15T15:00:04+00:00",
            "2026-03-16T00:00:04+09:00",
        ] {
            let parsed = <Timestamp as ScalarType>::parse(Value::String(input.to_owned()))
                .expect("valid input");
            assert_eq!(jiff::Timestamp::from(parsed), expected);
        }
    }

    #[test]
    fn input_rejects_a_date_and_non_strings() {
        assert!(<Timestamp as ScalarType>::parse(Value::String("2026-03-15".to_owned())).is_err());
        assert!(<Timestamp as ScalarType>::parse(Value::Boolean(true)).is_err());
        assert!(<Timestamp as ScalarType>::parse(Value::Null).is_err());
    }
}
