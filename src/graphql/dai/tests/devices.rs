//! The device list, the IP device rows, the device detail and search.

use review_database::{DaiImportRow, DaiSearchTarget, Store};
use review_protocol::types::DaiObservationKind as Kind;
use serde_json::{Value, json};

use super::{
    Agent, CUSTOMER, DAY, MINUTE, ack, activity, apply_all, data, data_at, default_site, enable,
    mac, mac_text, named_ack, refused, rfc3339, sensor, service, wall_clock,
};
use crate::graphql::TestSchema;

/// Returns the current id of the device holding MAC `n`.
pub(super) fn device_of_mac(store: &Store, n: u8) -> String {
    let result = store
        .dai_search(CUSTOMER, &mac_text(n), wall_clock())
        .unwrap();
    match &result.matches.first().unwrap().target {
        DaiSearchTarget::Device(device) => device.to_string(),
        DaiSearchTarget::IpDevice { .. } => panic!("a MAC names a device"),
    }
}

/// A customer with device identification on and one sensor in its default
/// site, the site's token, and an agent of the sensor.
pub(super) fn collecting(schema: &TestSchema) -> (Agent, String) {
    let store = schema.store();
    let a = sensor(&store, "a.example.com", CUSTOMER);
    enable(&store, CUSTOMER);
    let site = default_site(&store, CUSTOMER);
    (Agent::start(&store, &a, CUSTOMER), site)
}

fn devices(filter: &str, page: &str) -> String {
    format!(
        r#"{{ daiDevices(customerId: "{CUSTOMER}", filter: {{ {filter} }}{page}) {{
            totalCount
            pageInfo {{ hasPreviousPage hasNextPage }}
            edges {{ cursor node {{
                deviceId verdict activity representativeName firstSeen lastSeen
                currentIps {{ site ip start }}
                latestBinding {{ site ip start end endEstimated }}
            }} }}
        }} }}"#
    )
}

fn ip_devices(filter: &str, page: &str) -> String {
    format!(
        r#"{{ daiIpOnlyDevices(customerId: "{CUSTOMER}", filter: {{ {filter} }}{page}) {{
            totalCount
            pageInfo {{ hasPreviousPage hasNextPage }}
            edges {{ cursor node {{ site ip firstSeen lastSeen }} }}
        }} }}"#
    )
}

/// Returns the nodes of the connection `name` of `value`.
fn nodes<'a>(value: &'a Value, name: &str) -> Vec<&'a Value> {
    value[name]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| &edge["node"])
        .collect()
}

/// Returns the field `field` of each node of the connection `name`.
fn listed(value: &Value, name: &str, field: &str) -> Vec<Value> {
    nodes(value, name)
        .into_iter()
        .map(|node| node[field].clone())
        .collect()
}

/// Reads every page of the connection `name` that `query` gives for a page
/// argument, `size` rows at a time, forward and then backward, and returns
/// the rows of each direction in order, asserting `total` on every page.
async fn page_both_ways(
    schema: &TestSchema,
    query: impl Fn(&str) -> String,
    name: &str,
    size: usize,
    total: usize,
    now: i64,
) -> (Vec<Value>, Vec<Value>) {
    let mut forward = Vec::new();
    let mut after = String::new();
    loop {
        let value = data_at(schema, &query(&format!(", first: {size}{after}")), now).await;
        assert_eq!(value[name]["totalCount"], json!(total.to_string()));
        let edges = value[name]["edges"].as_array().unwrap();
        forward.extend(edges.iter().map(|edge| edge["node"].clone()));
        assert_eq!(
            value[name]["pageInfo"]["hasPreviousPage"],
            json!(!after.is_empty())
        );
        if value[name]["pageInfo"]["hasNextPage"] == json!(false) {
            break;
        }
        let cursor = edges.last().unwrap()["cursor"].as_str().unwrap();
        after = format!(r#", after: "{cursor}""#);
    }
    let mut backward = Vec::new();
    let mut before = String::new();
    loop {
        let value = data_at(schema, &query(&format!(", last: {size}{before}")), now).await;
        assert_eq!(value[name]["totalCount"], json!(total.to_string()));
        let edges = value[name]["edges"].as_array().unwrap();
        let mut page: Vec<Value> = edges.iter().map(|edge| edge["node"].clone()).collect();
        page.extend(backward);
        backward = page;
        assert_eq!(
            value[name]["pageInfo"]["hasNextPage"],
            json!(!before.is_empty())
        );
        if value[name]["pageInfo"]["hasPreviousPage"] == json!(false) {
            break;
        }
        let cursor = edges.first().unwrap()["cursor"].as_str().unwrap();
        before = format!(r#", before: "{cursor}""#);
    }
    (forward, backward)
}

#[tokio::test]
// One fixture, checked against every filter or kind in turn.
#[allow(clippy::too_many_lines)]
async fn the_device_list_pages_both_ways_and_applies_every_filter() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let ids: Vec<String> = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                ack(t(1), "10.0.0.1", 1),
                ack(t(1), "10.0.0.2", 2),
                ack(t(50), "10.0.0.2", 2),
                ack(t(20), "10.0.0.3", 3),
                ack(t(1), "192.168.1.4", 4),
                ack(t(1), "10.0.0.5", 5),
                // An address seen with no device is no device.
                activity(t(2), t(3), "10.0.0.21"),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(60));
        apply_all(&store);
        (1..=5).map(|n| device_of_mac(&store, n)).collect()
    };
    data(
        &schema,
        &format!(
            r#"mutation {{ setDaiDeviceStates(customerId: "{CUSTOMER}", deviceIds: ["{}"], verdict: CONFIRMED) }}"#,
            ids[4]
        ),
    )
    .await;
    data(
        &schema,
        &format!(
            r#"mutation {{ setDaiDeviceStates(customerId: "{CUSTOMER}", deviceIds: ["{}"], activity: HIDDEN) }}"#,
            ids[2]
        ),
    )
    .await;
    let now = t(55);
    let mut sorted = ids.clone();
    sorted.sort_unstable();

    let (forward, backward) =
        page_both_ways(&schema, |page| devices("", page), "daiDevices", 2, 5, now).await;
    let expected: Vec<Value> = sorted.iter().map(|id| json!(id)).collect();
    let ids_of = |nodes: &[Value]| -> Vec<Value> {
        nodes.iter().map(|node| node["deviceId"].clone()).collect()
    };
    assert_eq!(ids_of(&forward), expected);
    assert_eq!(ids_of(&backward), expected);

    // A device with a binding in effect now lists it; one without lists its
    // latest binding.
    let node = |id: &str| forward.iter().find(|node| node["deviceId"] == id).unwrap();
    assert_eq!(node(&ids[1])["currentIps"][0]["ip"], json!("10.0.0.2"));
    assert_eq!(node(&ids[1])["currentIps"][0]["site"], json!(site));
    assert_eq!(node(&ids[1])["latestBinding"], Value::Null);
    assert_eq!(node(&ids[0])["currentIps"], json!([]));
    assert_eq!(
        node(&ids[0])["latestBinding"],
        json!({
            "site": site, "ip": "10.0.0.1", "start": rfc3339(t(1)),
            "end": rfc3339(t(11)), "endEstimated": true,
        })
    );
    assert_eq!(node(&ids[0])["verdict"], json!("OBSERVED"));
    assert_eq!(node(&ids[0])["activity"], json!("ACTIVE"));
    assert_eq!(node(&ids[0])["firstSeen"], json!(rfc3339(t(1))));

    for (filter, expected) in [
        (format!(r#"sites: ["{site}"]"#), sorted.clone()),
        (r#"sites: ["nosuchst"]"#.to_string(), vec![]),
        ("verdicts: [CONFIRMED]".to_string(), vec![ids[4].clone()]),
        ("verdicts: [OBSERVED], activities: [ACTIVE]".to_string(), {
            let mut ids = vec![ids[0].clone(), ids[1].clone(), ids[3].clone()];
            ids.sort_unstable();
            ids
        }),
        ("activities: [HIDDEN]".to_string(), vec![ids[2].clone()]),
        (
            r#"network: "192.168.0.0/16""#.to_string(),
            vec![ids[3].clone()],
        ),
        (
            format!(
                r#"seen: {{ from: "{}", to: "{}" }}"#,
                rfc3339(t(15)),
                rfc3339(t(25))
            ),
            {
                let mut ids = vec![ids[1].clone(), ids[2].clone()];
                ids.sort_unstable();
                ids
            },
        ),
    ] {
        let value = data_at(&schema, &devices(&filter, ""), now).await;
        assert_eq!(
            listed(&value, "daiDevices", "deviceId"),
            expected.iter().map(|id| json!(id)).collect::<Vec<_>>(),
            "{filter}"
        );
        assert_eq!(
            value["daiDevices"]["totalCount"],
            json!(expected.len().to_string()),
            "{filter}"
        );
    }

    let error = refused(&schema, &devices(r#"network: "10.0.0.0/33""#, "")).await;
    assert!(error.message.contains("network"), "{}", error.message);
}

#[tokio::test]
async fn ip_device_rows_are_addresses_seen_unbound_in_the_last_30_days() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                ack(t(1), "10.0.0.1", 1),
                ack(t(1), "10.0.0.7", 7),
                // Bound at its last seen time.
                activity(t(2), t(3), "10.0.0.1"),
                activity(t(2), t(3), "10.0.0.21"),
                activity(t(5), t(6), "10.0.0.22"),
                activity(t(5), t(6), "192.168.1.22"),
                // Last seen after the binding ended.
                activity(t(10), t(14), "10.0.0.7"),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease, Kind::IpActivity], t(60));
        apply_all(&store);
    }
    let now = t(55);
    let row = |addr: &str, first: i64, last: i64| json!({ "site": site, "ip": addr, "firstSeen": rfc3339(first), "lastSeen": rfc3339(last) });
    let all = vec![
        row("10.0.0.7", t(10), t(14)),
        row("10.0.0.21", t(2), t(3)),
        row("10.0.0.22", t(5), t(6)),
        row("192.168.1.22", t(5), t(6)),
    ];

    let (forward, backward) = page_both_ways(
        &schema,
        |page| ip_devices("", page),
        "daiIpOnlyDevices",
        3,
        4,
        now,
    )
    .await;
    assert_eq!(forward, all);
    assert_eq!(backward, all);

    for (filter, expected) in [
        (r#"network: "10.0.0.0/8""#.to_string(), all[..3].to_vec()),
        (
            format!(
                r#"seen: {{ from: "{}", to: "{}" }}"#,
                rfc3339(t(4)),
                rfc3339(t(5))
            ),
            all[2..].to_vec(),
        ),
        (format!(r#"sites: ["{site}"]"#), all.clone()),
        (r#"sites: ["nosuchst"]"#.to_string(), vec![]),
    ] {
        let value = data_at(&schema, &ip_devices(&filter, ""), now).await;
        assert_eq!(
            nodes(&value, "daiIpOnlyDevices"),
            expected.iter().collect::<Vec<_>>(),
            "{filter}"
        );
        assert_eq!(
            value["daiIpOnlyDevices"]["totalCount"],
            json!(expected.len().to_string())
        );
    }

    // They are not devices.
    let value = data_at(&schema, &devices("", ""), now).await;
    assert_eq!(value["daiDevices"]["totalCount"], json!("2"));

    // Last seen more than 30 days ago.
    let value = data_at(&schema, &ip_devices("", ""), t(6) + 30 * DAY + MINUTE).await;
    assert_eq!(nodes(&value, "daiIpOnlyDevices"), vec![&all[0]],);
}

fn detail(device: &str) -> String {
    format!(
        r#"{{ daiDevice(customerId: "{CUSTOMER}", deviceId: "{device}") {{
            requestedId deviceId aliasFollowed
            identifiers {{ kind value }}
            names {{ value source }} representativeName
            assetId memo version
            ipHistory {{ site ip start }}
            services {{ port protocol removed notSeen lastSeen }}
            aliases {{ deviceId reason }}
        }} }}"#
    )
}

#[tokio::test]
async fn the_detail_follows_an_old_id_and_marks_services_not_seen() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let (first, second) = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                named_ack(t(1), "10.0.0.1", 1, "desk-01"),
                ack(t(1), "10.0.0.2", 2),
                service(t(2), "10.0.0.1", 22),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(60));
        apply_all(&store);
        (device_of_mac(&store, 1), device_of_mac(&store, 2))
    };

    let value = data_at(&schema, &detail(&first), t(55)).await;
    let device = &value["daiDevice"];
    assert_eq!(device["requestedId"], json!(first));
    assert_eq!(device["deviceId"], json!(first));
    assert_eq!(device["aliasFollowed"], json!(false));
    assert_eq!(
        device["identifiers"],
        json!([{ "kind": "MAC", "value": mac_text(1) }])
    );
    assert_eq!(
        device["names"],
        json!([{ "value": "desk-01", "source": "DHCP" }])
    );
    assert_eq!(device["representativeName"], json!("desk-01"));
    assert_eq!(
        device["ipHistory"],
        json!([{ "site": site, "ip": "10.0.0.1", "start": rfc3339(t(1)) }])
    );
    assert_eq!(
        device["services"],
        json!([{ "port": 22, "protocol": 6, "removed": false, "notSeen": false, "lastSeen": rfc3339(t(2)) }])
    );
    // Unseen for more than 30 days.
    let value = data_at(&schema, &detail(&first), t(2) + 30 * DAY + MINUTE).await;
    assert_eq!(value["daiDevice"]["services"][0]["notSeen"], json!(true));

    // An old id returns the current device.
    data(
        &schema,
        &format!(
            r#"mutation {{ mergeDaiDevices(customerId: "{CUSTOMER}", survivor: "{first}", others: ["{second}"]) }}"#
        ),
    )
    .await;
    let value = data_at(&schema, &detail(&second), t(55)).await;
    let device = &value["daiDevice"];
    assert_eq!(device["requestedId"], json!(second));
    assert_eq!(device["deviceId"], json!(first));
    assert_eq!(device["aliasFollowed"], json!(true));
    assert_eq!(
        device["aliases"],
        json!([{ "deviceId": second, "reason": "MERGED" }])
    );

    // An unknown id is no device; text that is no id is refused.
    let value = data_at(
        &schema,
        &detail("00000000-0000-4000-8000-000000000000"),
        t(55),
    )
    .await;
    assert_eq!(value, json!({ "daiDevice": null }));
    let error = refused(&schema, &detail("desk-01")).await;
    assert!(error.message.contains("desk-01"), "{}", error.message);
}

fn search(text: &str) -> String {
    format!(
        r#"{{ daiSearch(customerId: "{CUSTOMER}", text: {text:?}) {{
            truncated
            matches {{ matched target {{
                __typename
                ... on DaiSearchDevice {{ deviceId }}
                ... on DaiSearchIpDevice {{ site ip lastSeen }}
            }} }}
        }} }}"#
    )
}

fn device_match(matched: &str, device: &str) -> Value {
    json!({ "matched": matched, "target": { "__typename": "DaiSearchDevice", "deviceId": device } })
}

#[tokio::test]
async fn search_finds_by_each_kind_and_truncates_beyond_100() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let (named, lettered, merged_away, asset) = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                named_ack(t(1), "10.0.0.1", 1, "Printer-Lobby"),
                ack(t(1), "10.0.0.2", 0xab),
                ack(t(1), "10.0.0.3", 3),
                activity(t(2), t(3), "10.0.0.21"),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease, Kind::IpActivity], t(60));
        apply_all(&store);
        store
            .import_dai_devices(
                CUSTOMER,
                &[DaiImportRow {
                    asset_id: "ASSET-77".to_string(),
                    macs: vec![mac(77)],
                    ..DaiImportRow::default()
                }],
            )
            .unwrap();
        (
            device_of_mac(&store, 1),
            device_of_mac(&store, 0xab),
            device_of_mac(&store, 3),
            device_of_mac(&store, 77),
        )
    };
    data(
        &schema,
        &format!(
            r#"mutation {{ mergeDaiDevices(customerId: "{CUSTOMER}", survivor: "{lettered}", others: ["{merged_away}"]) }}"#
        ),
    )
    .await;
    let now = t(55);
    let found = |value: &Value| value["daiSearch"]["matches"].clone();

    for (text, expected) in [
        ("10.0.0.1", vec![device_match("IP", &named)]),
        ("02:00:00:00:00:ab", vec![device_match("MAC", &lettered)]),
        ("02:00:00:00:00:AB", vec![device_match("MAC", &lettered)]),
        ("02-00-00-00-00-Ab", vec![device_match("MAC", &lettered)]),
        ("0200.0000.00AB", vec![device_match("MAC", &lettered)]),
        ("ASSET-77", vec![device_match("ASSET_ID", &asset)]),
        ("printer-lob", vec![device_match("NAME", &named)]),
        ("LOBBY", vec![device_match("NAME", &named)]),
        (named.as_str(), vec![device_match("DEVICE_ID", &named)]),
        (
            merged_away.as_str(),
            vec![device_match("OLD_DEVICE_ID", &lettered)],
        ),
        (
            "10.0.0.21",
            vec![json!({ "matched": "IP", "target": {
                "__typename": "DaiSearchIpDevice", "site": site, "ip": "10.0.0.21",
                "lastSeen": rfc3339(t(3)),
            } })],
        ),
    ] {
        let value = data_at(&schema, &search(text), now).await;
        assert_eq!(found(&value), json!(expected), "{text}");
        assert_eq!(value["daiSearch"]["truncated"], json!(false), "{text}");
    }

    // More than 100 matches.
    let rows: Vec<DaiImportRow> = (0..101)
        .map(|n| DaiImportRow {
            asset_id: format!("BULK-{n}"),
            name: Some(format!("bulk-{n}")),
            ..DaiImportRow::default()
        })
        .collect();
    schema.store().import_dai_devices(CUSTOMER, &rows).unwrap();
    let value = data_at(&schema, &search("bulk"), now).await;
    assert_eq!(found(&value).as_array().unwrap().len(), 100);
    assert_eq!(value["daiSearch"]["truncated"], json!(true));
}
