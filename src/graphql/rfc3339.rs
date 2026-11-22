//! The check on a time that is kept as text and passed on to an engine.
//!
//! `REconverge` parses such a time as RFC 3339 with an offset, so the text is
//! held to that shape first and then parsed as a [`jiff::Timestamp`]. The text
//! itself is passed on as received.

use std::sync::LazyLock;

use jiff::SignedDuration;
use regex::Regex;

const NANOS_PER_SECOND: i32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// The shape of RFC 3339 with an offset.
///
/// Digits are spelled `[0-9]` rather than `\d`, which in `regex` also matches
/// non-ASCII digits that neither jiff nor `REconverge` accepts.
const RFC3339_WITH_OFFSET: &str = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$";

static SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(RFC3339_WITH_OFFSET).expect("the RFC 3339 pattern is a valid regex")
});

/// Why a text is not RFC 3339 with an offset.
#[derive(Debug)]
pub(super) enum Rfc3339Error {
    /// The text does not have the shape.
    Shape,
    /// The text has the shape but is not a time jiff can hold.
    Parse(jiff::Error),
}

impl Rfc3339Error {
    /// Returns the detail appended to a refusal message: jiff's error text
    /// after `": "` when parsing failed, nothing when the shape did not match.
    pub(super) fn detail(&self) -> String {
        match self {
            Self::Shape => String::new(),
            Self::Parse(e) => format!(": {e}"),
        }
    }
}

/// Parses `text` as RFC 3339 with an offset.
///
/// # Errors
///
/// Returns [`Rfc3339Error::Shape`] if `text` does not have the shape of RFC
/// 3339 with an offset, and [`Rfc3339Error::Parse`] if it has the shape but
/// is not a time a [`jiff::Timestamp`] can hold.
pub(super) fn parse(text: &str) -> Result<jiff::Timestamp, Rfc3339Error> {
    if !SHAPE.is_match(text) {
        return Err(Rfc3339Error::Shape);
    }
    text.parse().map_err(Rfc3339Error::Parse)
}

/// A time read from RFC 3339 text, ordered and measured as `REconverge`
/// reads it, leap seconds included.
///
/// jiff reads a leap second (`:60`) as `:59`, so a window whose bounds fall
/// in and just before a leap second would be ordered differently from how
/// `REconverge` orders the text it is given. `REconverge` keeps a leap second
/// as its `:59` second with one more second of fraction, so `:60.5` is later
/// than every `:59.x` and earlier than the next minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LeapAwareTime {
    /// Whole seconds since the Unix epoch, rounded down, with a leap second
    /// counted as its `:59`.
    second: i64,
    /// Nanoseconds past `second`, one second or more inside a leap second.
    nanosecond: i32,
}

impl LeapAwareTime {
    /// Parses `text` as RFC 3339 with an offset, keeping a leap second.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`parse`].
    pub(super) fn parse(text: &str) -> Result<Self, Rfc3339Error> {
        let timestamp = parse(text)?;
        let mut second = timestamp.as_second();
        let mut nanosecond = timestamp.subsec_nanosecond();
        if nanosecond < 0 {
            second -= 1;
            nanosecond += NANOS_PER_SECOND;
        }
        // The shape check has passed, so the text is ASCII and its seconds
        // are the two digits after `YYYY-MM-DDTHH:MM:`.
        if text.get(17..19) == Some("60") {
            nanosecond += NANOS_PER_SECOND;
        }
        Ok(Self { second, nanosecond })
    }

    /// Returns the time from `earlier` to `self` as `REconverge` measures it.
    ///
    /// Away from leap seconds this is the plain difference. A leap second
    /// counts as one second only where the later time is later in its day
    /// than the earlier one, as `REconverge`'s time arithmetic does.
    #[must_use]
    pub(super) fn duration_since(self, earlier: Self) -> SignedDuration {
        let mut seconds = self.second - earlier.second;
        let time_of_day = self.second.rem_euclid(SECONDS_PER_DAY);
        let earlier_time_of_day = earlier.second.rem_euclid(SECONDS_PER_DAY);
        if time_of_day > earlier_time_of_day && earlier.nanosecond >= NANOS_PER_SECOND {
            seconds += 1;
        } else if time_of_day < earlier_time_of_day && self.nanosecond >= NANOS_PER_SECOND {
            seconds -= 1;
        }
        SignedDuration::from_secs(seconds)
            + SignedDuration::from_nanos(i64::from(self.nanosecond - earlier.nanosecond))
    }
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::{LeapAwareTime, Rfc3339Error, parse};

    #[test]
    fn rfc3339_with_an_offset_is_accepted() {
        for (text, expected) in [
            ("2026-03-15T15:00:04Z", "2026-03-15T15:00:04Z"),
            ("2026-03-15t15:00:04z", "2026-03-15T15:00:04Z"),
            (
                "2026-03-15T15:00:04.123456789+09:00",
                "2026-03-15T06:00:04.123456789Z",
            ),
            ("2026-03-15 15:00:04-05:30", "2026-03-15T20:30:04Z"),
            ("9999-12-30T22:00:00Z", "9999-12-30T22:00:00Z"),
            (
                "9999-12-30T22:00:00.999999999Z",
                "9999-12-30T22:00:00.999999999Z",
            ),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59Z"),
        ] {
            assert_eq!(parse(text).expect(text).to_string(), expected);
        }
    }

    #[test]
    fn other_forms_fail_the_shape() {
        for text in [
            "2026-03-15T15:00:04",
            "2026-03-15T15:00:04+09",
            "2026-03-15T15:00:04+0900",
            "2026-03-15T15:00:04+24:00",
            "2026-03-15T15:00:04Z[Asia/Seoul]",
            "2026-03-15T15:00:04,5Z",
            "20260315T150004Z",
            "2026-03-15T15:00:04Z\n",
            "2026-03-15",
            "yesterday",
        ] {
            assert!(matches!(parse(text), Err(Rfc3339Error::Shape)), "{text}");
        }
    }

    #[test]
    fn shaped_text_jiff_cannot_hold_fails_parsing() {
        for text in [
            "2026-03-15T15:00:04.1234567890Z",
            "9999-12-31T00:00:00Z",
            "9999-12-30T22:00:01Z",
            "2026-02-30T15:00:04Z",
        ] {
            let error = parse(text).expect_err(text);
            assert!(matches!(error, Rfc3339Error::Parse(_)), "{text}");
            assert!(error.detail().starts_with(": "), "{text}");
        }
    }

    fn leap_aware(text: &str) -> LeapAwareTime {
        LeapAwareTime::parse(text).expect(text)
    }

    #[test]
    fn a_leap_second_is_after_its_59th_second_and_before_the_next_minute() {
        let ordered = [
            "2016-12-31T23:59:59Z",
            "2016-12-31T23:59:59.5Z",
            "2016-12-31T23:59:60Z",
            "2016-12-31T23:59:60.5Z",
            "2017-01-01T00:00:00Z",
        ];
        for pair in ordered.windows(2) {
            let [earlier, later] = pair else {
                unreachable!("`windows(2)` yields pairs")
            };
            assert!(
                leap_aware(earlier) < leap_aware(later),
                "{earlier} < {later}"
            );
        }
        assert_eq!(
            leap_aware("2017-01-01T08:59:60+09:00"),
            leap_aware("2016-12-31T23:59:60Z")
        );
    }

    #[test]
    fn times_before_the_epoch_keep_their_order() {
        assert!(leap_aware("1969-12-31T23:59:59.5Z") < leap_aware("1970-01-01T00:00:00Z"));
        assert!(leap_aware("1969-12-31T23:59:59Z") < leap_aware("1969-12-31T23:59:59.5Z"));
    }

    #[test]
    fn durations_count_a_leap_second_as_the_engine_does() {
        for (earlier, later, expected) in [
            ("2016-12-31T23:59:59Z", "2016-12-31T23:59:60Z", 1_000),
            ("2016-12-31T23:59:59Z", "2016-12-31T23:59:60.5Z", 1_500),
            ("2016-12-31T23:59:00Z", "2016-12-31T23:59:60.5Z", 60_500),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60.5Z", 500),
            ("2016-12-31T23:59:60Z", "2017-01-01T00:00:00Z", 0),
            ("2016-12-31T23:59:60Z", "2017-01-01T00:00:01Z", 1_000),
            ("2016-12-31T00:00:00Z", "2016-12-31T23:59:60Z", 86_400_000),
            ("2026-03-15T15:00:04Z", "2026-03-15T15:00:05.25Z", 1_250),
        ] {
            assert_eq!(
                leap_aware(later).duration_since(leap_aware(earlier)),
                SignedDuration::from_millis(expected),
                "{earlier} to {later}"
            );
        }
    }
}
