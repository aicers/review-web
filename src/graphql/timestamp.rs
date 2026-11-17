pub use jiff::Timestamp;

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
