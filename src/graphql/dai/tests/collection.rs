//! The collection status and the candidate unregistered ranges.

use review_database::Store;
use review_protocol::types::{
    DaiObservationKind as Kind, DaiRangeBlock, DaiRangeDay, DaiRangeEvidence, DaiRangeGrant,
    DaiRangeUnit,
};
use serde_json::{Value, json};

use super::devices::collecting;
use super::{
    CUSTOMER, DAY, MINUTE, NS, ack, apply_all, data_at, default_site, refused, rfc3339, wall_clock,
};
use crate::graphql::TestSchema;

/// Returns the UTC date of `time` as days since the UNIX epoch.
fn date_of(time: i64) -> i32 {
    i32::try_from(time.div_euclid(DAY)).unwrap()
}

/// Returns `date`, days since the UNIX epoch, as `YYYY-MM-DD`.
fn date_text(date: i32) -> String {
    jiff::Timestamp::from_second(i64::from(date) * DAY / NS)
        .unwrap()
        .strftime("%Y-%m-%d")
        .to_string()
}

#[tokio::test]
async fn the_collection_status_reports_receipts_cursors_gaps_and_counts() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let sensor = agent.sensor.clone();
    {
        let store = schema.store();
        // An observation whose last seen time is outside its slot is
        // filtered at receipt.
        let mut stray = ack(t(2), "10.0.0.2", 2);
        stray.last = t(7);
        agent.send(&store, vec![ack(t(1), "10.0.0.1", 1), stray]);
        agent.reach(&store, &[Kind::DhcpLease], t(30));
        agent.skip(&store, Kind::DhcpLease, t(40));
        agent.reach(&store, &[Kind::DhcpLease], t(60));
        apply_all(&store);
    }
    let today = date_text(date_of(wall_clock()));
    let query = format!(
        r#"{{ daiCollectionStatus(customerId: "{CUSTOMER}") {{
            sites {{ site receipts {{ kind time sensor }} quietSensors unsentPairs {{ sensor kind }} }}
            sensors {{ sensor site lastRecordTime cursors {{ kind cursor lagSecs }} }}
            catchupGaps {{ sensor kind start end }}
            skippedByCatchup {{ date count }}
            relaySiteUnknown {{ date count }}
            filteredAtReceipt {{ date count }}
            notApplied {{ date count }}
            candidateRanges
        }} }}"#
    );
    let mut value = data_at(&schema, &query, t(61)).await;
    let status = value["daiCollectionStatus"].as_object_mut().unwrap();

    let receipts = status["sites"][0]["receipts"].as_array_mut().unwrap();
    assert!(receipts[0]["time"].is_string(), "{receipts:?}");
    receipts[0]["time"] = Value::Null;
    assert_eq!(
        status["sites"],
        json!([{
            "site": site,
            "receipts": [
                { "kind": "DHCP_LEASE", "time": null, "sensor": sensor },
                { "kind": "KERBEROS", "time": null, "sensor": null },
                { "kind": "NTLM", "time": null, "sensor": null },
            ],
            "quietSensors": [],
            "unsentPairs": [
                { "sensor": sensor, "kind": "KERBEROS" },
                { "sensor": sensor, "kind": "NTLM" },
            ],
        }])
    );
    let sensors = status["sensors"].as_array().unwrap();
    assert_eq!(sensors.len(), 1);
    assert_eq!(sensors[0]["sensor"], json!(sensor));
    assert_eq!(sensors[0]["site"], json!(site));
    assert_eq!(sensors[0]["lastRecordTime"], json!(rfc3339(t(60))));
    let cursors = sensors[0]["cursors"].as_array().unwrap();
    assert_eq!(cursors.len(), 8);
    assert_eq!(
        cursors[0],
        json!({ "kind": "DHCP_LEASE", "cursor": rfc3339(t(60)), "lagSecs": "60" })
    );
    assert_eq!(
        status["catchupGaps"],
        json!([{ "sensor": sensor, "kind": "DHCP_LEASE", "start": rfc3339(t(30)), "end": rfc3339(t(40)) }])
    );
    assert_eq!(
        status["skippedByCatchup"],
        json!([{ "date": today, "count": "2" }])
    );
    assert_eq!(
        status["filteredAtReceipt"],
        json!([{ "date": today, "count": "1" }])
    );
    assert_eq!(status["relaySiteUnknown"], json!([]));
    assert_eq!(status["notApplied"], json!([]));
    assert_eq!(status["candidateRanges"], json!("0"));
}

/// Stores, for `sensor`, the range days of the three dates before the date
/// of `now`, each counting `blocks`.
fn range_days(store: &Store, sensor: &str, customer: u32, blocks: &[&str], now: i64) {
    let today = date_of(now);
    for date in today - 3..today {
        let unit = DaiRangeUnit {
            sensor: sensor.to_string(),
            date,
            evidence: DaiRangeEvidence::Sensor,
        };
        let restore_generation = store.dai_restore_generation().unwrap();
        let Some(DaiRangeGrant::Granted {
            version,
            lease_token,
            ..
        }) = store
            .begin_dai_range_day(&unit, restore_generation, now)
            .unwrap()
        else {
            panic!("the range day is granted");
        };
        let networks = store.customer_networks_map().get(customer).unwrap();
        let day = DaiRangeDay {
            restore_generation,
            config_epoch: store.dai_sensor_config_epoch(sensor).unwrap(),
            network_digest: review_database::dai_network_digest(networks.as_ref())
                .unwrap()
                .digest,
            unit,
            version,
            mark: None,
            lease_token,
            blocks: blocks
                .iter()
                .map(|block| DaiRangeBlock {
                    block: block.parse().unwrap(),
                    distinct_addrs: 5,
                    conns: 10,
                    saturated: false,
                })
                .collect(),
            subnets: Vec::new(),
        };
        store.send_dai_range_day(&day, now).unwrap();
    }
}

#[tokio::test]
async fn an_ignored_range_leaves_the_candidates_until_it_is_unignored() {
    let schema = TestSchema::new().await;
    let (agent, site) = collecting(&schema);
    let now = wall_clock();
    range_days(
        &schema.store(),
        &agent.sensor,
        CUSTOMER,
        &["10.20.30.0/24", "100.64.1.0/24"],
        now,
    );
    assert_eq!(default_site(&schema.store(), CUSTOMER), site);
    let today = date_of(now);
    let candidate = |range: &str, cgnat: bool| {
        json!({
            "range": range,
            "seenAddrs": "5",
            "seenAddrsAtLeast": false,
            "values": [{ "evidence": "SENSOR", "count": "3" }],
            "firstDate": date_text(today - 3),
            "lastDate": date_text(today - 1),
            "sites": [site],
            "cgnat": cgnat,
        })
    };
    let candidates = format!(
        r#"{{ daiRangeCandidates(customerId: "{CUSTOMER}") {{
            range seenAddrs seenAddrsAtLeast values {{ evidence count }} firstDate lastDate sites cgnat
        }} }}"#
    );
    let ignored = format!(
        r#"{{ daiIgnoredRanges(customerId: "{CUSTOMER}") {{ range ignoredAt account }} }}"#
    );
    let ignore = |range: &str, account: &str| {
        format!(
            r#"mutation {{ ignoreDaiRangeCandidate(customerId: "{CUSTOMER}", range: "{range}", account: "{account}") }}"#
        )
    };
    let unignore = |range: &str| {
        format!(
            r#"mutation {{ unignoreDaiRangeCandidate(customerId: "{CUSTOMER}", range: "{range}") }}"#
        )
    };
    let both = json!({ "daiRangeCandidates": [
        candidate("10.20.30.0/24", false),
        candidate("100.64.1.0/24", true),
    ] });
    assert_eq!(data_at(&schema, &candidates, now).await, both);
    let status =
        format!(r#"{{ daiCollectionStatus(customerId: "{CUSTOMER}") {{ candidateRanges }} }}"#);
    assert_eq!(
        data_at(&schema, &status, now).await,
        json!({ "daiCollectionStatus": { "candidateRanges": "2" } })
    );

    // Ignoring normalizes the range and records the account, trimmed.
    assert_eq!(
        data_at(&schema, &ignore("10.20.30.7/24", "  alice "), now).await,
        json!({ "ignoreDaiRangeCandidate": "10.20.30.0/24" })
    );
    assert_eq!(
        data_at(&schema, &candidates, now).await,
        json!({ "daiRangeCandidates": [candidate("100.64.1.0/24", true)] })
    );
    let alice = json!({ "daiIgnoredRanges": [
        { "range": "10.20.30.0/24", "ignoredAt": rfc3339(now), "account": "alice" },
    ] });
    assert_eq!(data_at(&schema, &ignored, now).await, alice);
    // Again changes nothing.
    data_at(&schema, &ignore("10.20.30.0/24", "bob"), now + MINUTE).await;
    assert_eq!(data_at(&schema, &ignored, now).await, alice);

    for (mutation, cause) in [
        (ignore("10.20.30.0/24", "  "), "account"),
        (ignore("10.20.30", "alice"), "10.20.30"),
        (unignore("not a range"), "not a range"),
    ] {
        let error = refused(&schema, &mutation).await;
        assert!(error.message.contains(cause), "{}", error.message);
    }

    assert_eq!(
        data_at(&schema, &unignore("10.20.30.0/24"), now).await,
        json!({ "unignoreDaiRangeCandidate": true })
    );
    assert_eq!(
        data_at(&schema, &unignore("10.20.30.0/24"), now).await,
        json!({ "unignoreDaiRangeCandidate": false })
    );
    assert_eq!(data_at(&schema, &candidates, now).await, both);
    assert_eq!(
        data_at(&schema, &ignored, now).await,
        json!({ "daiIgnoredRanges": [] })
    );
}
