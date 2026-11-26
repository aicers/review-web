//! Reading detection events in the order they arrived, and the earliest
//! stored detection time.

use std::fmt::Write as _;

use async_graphql::{Context, ID, Result, SimpleObject};
use review_database::{
    TriagePolicyInput as DbTriagePolicyInput,
    event::{ArrivalKey, EventFilter},
};
use tracing::error;

use super::{
    DEFAULT_CONNECTION_SIZE, EventTriagePolicyInput, convert_event_triage_policies,
    detection::DetectionEvent, readable_event,
};
use crate::{
    error_with_caller,
    graphql::{
        MAX_CONNECTION_SIZE,
        customer_access::{check_customer_membership, customer_sensor_names},
        timestamp::Timestamp,
    },
};

/// The most arrival index rows one `detectionEventsByArrival` call scans.
const MAX_ARRIVAL_SCAN: usize = 10_000;
/// The length of a cursor: two hex digits for each byte of an arrival key.
const ARRIVAL_CURSOR_LEN: usize = 48;

/// A page of detection events in the order they arrived.
#[derive(SimpleObject)]
pub(super) struct DetectionEventArrivalPage {
    /// The customer's events among the scanned index rows, in arrival order.
    events: Vec<DetectionEvent>,
    /// The position of the last index row scanned, to pass as `after` to read
    /// on. It moves forward even when no scanned row held an event of the
    /// customer. It is null only when nothing was scanned; the caller then
    /// keeps its previous cursor.
    cursor: Option<String>,
    /// Whether any index row exists after `cursor`, or after `after` when
    /// `cursor` is null.
    has_more: bool,
}

/// Reads, in arrival order, the events of `customer_id`'s sensors after
/// `after`, scoring each against `policies` when they are given.
pub(super) fn load_by_arrival(
    ctx: &Context<'_>,
    customer_id: &ID,
    after: Option<&str>,
    first: Option<i32>,
    policies: Option<&[EventTriagePolicyInput]>,
) -> Result<DetectionEventArrivalPage> {
    let id = customer_id
        .as_str()
        .parse::<u32>()
        .map_err(|_| "invalid customer ID")?;
    check_customer_membership(ctx, customer_id)?;
    let first = page_size(first)?;
    let after = after.map(decode_cursor).transpose()?;
    let policies = policies
        .map(convert_event_triage_policies)
        .transpose()?
        .unwrap_or_default();

    let store = crate::graphql::get_store(ctx)?;
    let sensors = customer_sensor_names(&store, id)?
        .into_iter()
        .collect::<Vec<_>>();
    let policy_sensors = store.time_series_policy_sensors()?;
    let filter = EventFilter::new(
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some((sensors, policy_sensors)),
        None,
        None,
        None,
    );
    let page = store
        .events()
        .read_by_arrival(&filter, after, first, MAX_ARRIVAL_SCAN)
        .map_err(|e| {
            error_with_caller!(ctx, "Failed to read events by arrival: {e:#}");
            async_graphql::Error::new("failed to read events")
        })?;

    let events = page
        .events
        .into_iter()
        .map(|(key, record)| {
            let scores = scores_of(&record, &policies);
            DetectionEvent::with_triage_scores(key, record, scores)
        })
        .collect();
    Ok(DetectionEventArrivalPage {
        events,
        cursor: page.last_scanned.map(|key| encode_cursor(&key)),
        has_more: page.has_more,
    })
}

/// Returns the detection time of the stored record with the smallest key in
/// signed `i128` order, or `None` if no readable record is stored.
pub(super) fn oldest_event_time(ctx: &Context<'_>) -> Result<Option<Timestamp>> {
    let store = crate::graphql::get_store(ctx)?;
    let events = store.events();
    for item in events.iter_forward() {
        let Some((key, _)) = readable_event(ctx, item)? else {
            continue;
        };
        return Ok(Some(key_time(key)));
    }
    Ok(None)
}

/// Returns the detection time a record key starts with: its upper 64 bits as
/// epoch nanoseconds.
fn key_time(key: i128) -> Timestamp {
    jiff::Timestamp::from_nanosecond(key >> 64)
        .expect(
            "the upper 64 bits of an `i128` fit in `i64`, and jiff spans every `i64` nanosecond",
        )
        .into()
}

/// Returns `first`, or the default page size when it is absent, refusing a
/// value outside 1 to `MAX_CONNECTION_SIZE`.
fn page_size(first: Option<i32>) -> Result<usize> {
    let Some(first) = first else {
        return Ok(DEFAULT_CONNECTION_SIZE);
    };
    if !(1..=MAX_CONNECTION_SIZE).contains(&first) {
        return Err(format!("`first` must be between 1 and {MAX_CONNECTION_SIZE}").into());
    }
    usize::try_from(first).map_err(|_| "`first` must be positive".into())
}

/// Returns the scores `record` gets against `policies`, or `None` when no
/// policy is given or none scores it.
fn scores_of(
    record: &review_database::StoredDetectionEvent,
    policies: &[DbTriagePolicyInput],
) -> Option<Vec<review_database::event::TriageScore>> {
    if policies.is_empty() {
        return None;
    }
    Some(record.score_against_policies(policies)).filter(|scores| !scores.is_empty())
}

/// Encodes an arrival key as its 24 bytes in lowercase hex.
fn encode_cursor(key: &ArrivalKey) -> String {
    key.to_bytes().iter().fold(
        String::with_capacity(ARRIVAL_CURSOR_LEN),
        |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a `String` cannot fail");
            hex
        },
    )
}

/// Decodes a cursor `encode_cursor` made, refusing anything that is not 48
/// hex digits.
fn decode_cursor(cursor: &str) -> Result<ArrivalKey> {
    const INVALID: &str = "invalid cursor `after`: expected 48 hex digits";

    if cursor.len() != ARRIVAL_CURSOR_LEN || !cursor.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(INVALID.into());
    }
    let mut bytes = [0_u8; ARRIVAL_CURSOR_LEN / 2];
    let (pairs, _) = cursor.as_bytes().as_chunks::<2>();
    for (byte, pair) in bytes.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).map_err(|_| INVALID)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| INVALID)?;
    }
    Ok(ArrivalKey::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip() {
        for key in [
            ArrivalKey::new(0, 0),
            ArrivalKey::new(1_700_000_000_000_000_000, -1),
            ArrivalKey::new(i64::MAX, i128::MIN),
        ] {
            let cursor = encode_cursor(&key);
            assert_eq!(cursor.len(), ARRIVAL_CURSOR_LEN);
            assert!(
                cursor
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert_eq!(decode_cursor(&cursor).unwrap(), key);
        }
    }

    #[test]
    fn malformed_cursors_are_refused() {
        for cursor in [
            "",
            "0",
            &"0".repeat(47),
            &"0".repeat(49),
            &"g".repeat(48),
            &format!("{}é", "0".repeat(46)),
            &format!("+{}", "0".repeat(47)),
        ] {
            assert!(decode_cursor(cursor).is_err(), "{cursor:?}");
        }
    }

    #[test]
    fn page_sizes_outside_one_to_the_maximum_are_refused() {
        assert_eq!(page_size(None).unwrap(), DEFAULT_CONNECTION_SIZE);
        assert_eq!(page_size(Some(1)).unwrap(), 1);
        assert_eq!(page_size(Some(100)).unwrap(), 100);
        for first in [0, 101, -1, i32::MIN, i32::MAX] {
            assert!(page_size(Some(first)).is_err(), "{first}");
        }
    }

    #[test]
    fn key_times_cross_the_unix_epoch() {
        assert_eq!(
            jiff::Timestamp::from(key_time(-1_i128 << 64)),
            jiff::Timestamp::from_nanosecond(-1).unwrap()
        );
        assert_eq!(
            jiff::Timestamp::from(key_time((5_i128 << 64) | 7)),
            jiff::Timestamp::from_nanosecond(5).unwrap()
        );
        for nanos in [i64::MIN, i64::MAX] {
            assert_eq!(
                jiff::Timestamp::from(key_time(i128::from(nanos) << 64)).as_nanosecond(),
                i128::from(nanos)
            );
        }
    }
}
