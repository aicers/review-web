//! The operator device operations.

use review_protocol::types::DaiObservationKind as Kind;
use serde_json::{Value, json};

use super::devices::{collecting, device_of_mac};
use super::{
    CUSTOMER, MINUTE, OTHER, ack, apply_all, data, data_at, default_site, mac_text, refused,
    rfc3339, sensor, service,
};
use crate::graphql::TestSchema;

fn import(customer: u32, rows: &[String]) -> String {
    format!(
        r#"mutation {{ importDaiDevices(customerId: "{customer}", rows: [{}]) {{
            outcome deviceId error {{ reason message deviceIds }}
        }} }}"#,
        rows.join(", ")
    )
}

fn row(
    asset: &str,
    macs: &[&str],
    fixed_ips: &[(Option<&str>, &str)],
    name: &str,
    note: &str,
) -> String {
    let fixed_ips = fixed_ips
        .iter()
        .map(|(site, addr)| match site {
            Some(site) => format!(r#"{{ site: "{site}", ip: "{addr}" }}"#),
            None => format!(r#"{{ ip: "{addr}" }}"#),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r"{{ assetId: {asset:?}, name: {name:?}, macs: {macs:?}, fixedIps: [{fixed_ips}], note: {note:?} }}"
    )
}

fn detail(device: &str) -> String {
    format!(
        r#"{{ daiDevice(customerId: "{CUSTOMER}", deviceId: "{device}") {{
            deviceId identifiers {{ kind value }} names {{ value source }} assetId memo
            fixedIps {{ site ip }} ipHistory {{ ip start }} verdict activity version
            services {{ port protocol removed }}
            changes {{ version kind source }}
        }} }}"#
    )
}

fn results(value: &Value) -> &Vec<Value> {
    value["importDaiDevices"].as_array().unwrap()
}

/// Returns the device holding the operator asset id `asset`, if any.
fn device_of_asset(schema: &TestSchema, asset: &str) -> Option<String> {
    let result = schema
        .store()
        .dai_search(CUSTOMER, asset, super::wall_clock())
        .unwrap();
    result.matches.into_iter().find_map(|hit| match hit.target {
        review_database::DaiSearchTarget::Device(device)
            if hit.matched == review_database::DaiSearchMatchKind::AssetId =>
        {
            Some(device.to_string())
        }
        _ => None,
    })
}

#[tokio::test]
async fn an_import_creates_attaches_and_updates_with_the_rows_values() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let observed = {
        let store = schema.store();
        agent.send(&store, vec![ack(agent.at(1), "10.0.0.1", 1)]);
        agent.reach(&store, &[Kind::DhcpLease], agent.at(10));
        apply_all(&store);
        device_of_mac(&store, 1)
    };
    let m = mac_text;

    let value = data(
        &schema,
        &import(
            CUSTOMER,
            &[
                row(
                    "A-1",
                    &[&m(0x11)],
                    &[(Some(&site), "10.0.0.31")],
                    "Desk",
                    "first",
                ),
                // MACs in other forms, and of an observed device.
                row("A-2", &["02-00-00-00-00-01"], &[], "", ""),
            ],
        ),
    )
    .await;
    let created = results(&value)[0]["deviceId"].as_str().unwrap().to_string();
    assert_eq!(
        results(&value),
        &vec![
            json!({ "outcome": "CREATED", "deviceId": created, "error": null }),
            json!({ "outcome": "ATTACHED", "deviceId": observed, "error": null }),
        ]
    );
    let value = data(&schema, &detail(&created)).await;
    let device = &value["daiDevice"];
    assert_eq!(device["assetId"], json!("A-1"));
    assert_eq!(device["memo"], json!("first"));
    assert_eq!(
        device["names"],
        json!([{ "value": "Desk", "source": "OPERATOR" }])
    );
    assert_eq!(
        device["fixedIps"],
        json!([{ "site": site, "ip": "10.0.0.31" }])
    );
    let identifiers = device["identifiers"].as_array().unwrap();
    assert!(identifiers.contains(&json!({ "kind": "MAC", "value": m(0x11) })));
    assert!(identifiers.contains(&json!({ "kind": "OPERATOR_ASSET_ID", "value": "A-1" })));
    assert_eq!(
        data(&schema, &detail(&observed)).await["daiDevice"]["assetId"],
        json!("A-2")
    );

    // A known asset id replaces the values with the row's.
    let value = data(
        &schema,
        &import(
            CUSTOMER,
            &[row(
                "A-1",
                &["0200.0000.0012"],
                &[(Some(&site), "10.0.0.32")],
                "Desk 2",
                "second",
            )],
        ),
    )
    .await;
    assert_eq!(
        results(&value),
        &vec![json!({ "outcome": "UPDATED", "deviceId": created, "error": null })]
    );
    let value = data(&schema, &detail(&created)).await;
    let device = &value["daiDevice"];
    assert_eq!(device["memo"], json!("second"));
    assert_eq!(
        device["names"],
        json!([{ "value": "Desk 2", "source": "OPERATOR" }])
    );
    assert_eq!(
        device["fixedIps"],
        json!([{ "site": site, "ip": "10.0.0.32" }])
    );
    let macs: Vec<&Value> = device["identifiers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|identifier| identifier["kind"] == "MAC")
        .map(|identifier| &identifier["value"])
        .collect();
    assert_eq!(macs, [&json!(m(0x12))]);
}

#[tokio::test]
async fn a_refused_row_writes_nothing_and_the_others_are_written_in_place() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let (one, two) = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                ack(agent.at(1), "10.0.0.1", 1),
                ack(agent.at(1), "10.0.0.2", 2),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease], agent.at(10));
        apply_all(&store);
        (device_of_mac(&store, 1), device_of_mac(&store, 2))
    };
    let m = mac_text;
    let value = data(
        &schema,
        &import(
            CUSTOMER,
            &[
                row("HOLDER", &[], &[(Some(&site), "10.0.0.40")], "", ""),
                row("TAKEN", &[&m(9)], &[], "", ""),
                row("A-1", &[], &[], "", ""),
                row("MERGE", &[&m(1), &m(2)], &[], "", ""),
                row("HELD", &[], &[(Some(&site), "10.0.0.40")], "", ""),
                row("BADMAC", &["zz:00:00:00:00:01"], &[], "", ""),
                row("GROUP", &["01:00:00:00:00:01"], &[], "", ""),
                row("BADIP", &[], &[(Some(&site), "10.0.0.999")], "", ""),
                row("", &[], &[], "", ""),
                row("A-1", &[], &[], "", ""),
                row("BADMAC", &[], &[], "", ""),
                row("NOSITE", &[], &[(Some("nosuchst"), "10.0.0.41")], "", ""),
                row("MISMATCH", &[&m(9)], &[], "", ""),
                row("A-2", &[], &[], "", ""),
            ],
        ),
    )
    .await;
    let results = results(&value);
    let holder = results[0]["deviceId"].as_str().unwrap().to_string();
    let taken = results[1]["deviceId"].as_str().unwrap().to_string();
    let mut merge = vec![one.clone(), two.clone()];
    merge.sort_unstable();
    let outcomes: Vec<(&Value, &Value, &Value)> = results
        .iter()
        .map(|result| {
            (
                &result["outcome"],
                &result["error"]["reason"],
                &result["error"]["deviceIds"],
            )
        })
        .collect();
    let null = Value::Null;
    assert_eq!(
        outcomes,
        [
            (&json!("CREATED"), &null, &null),
            (&json!("CREATED"), &null, &null),
            (&json!("CREATED"), &null, &null),
            (&json!("ERROR"), &json!("MERGE_FIRST"), &json!(merge)),
            (&json!("ERROR"), &json!("FIXED_IP_HELD"), &json!([holder])),
            (&json!("ERROR"), &json!("INVALID_MAC"), &json!([])),
            (&json!("ERROR"), &json!("INVALID_MAC"), &json!([])),
            (&json!("ERROR"), &json!("INVALID_IP"), &json!([])),
            (&json!("ERROR"), &json!("EMPTY_ASSET_ID"), &json!([])),
            (&json!("ERROR"), &json!("DUPLICATE_ASSET_ID"), &json!([])),
            // An earlier row refused here still has the asset id.
            (&json!("ERROR"), &json!("DUPLICATE_ASSET_ID"), &json!([])),
            (&json!("ERROR"), &json!("UNKNOWN_SITE"), &json!([])),
            (
                &json!("ERROR"),
                &json!("ASSET_ID_MISMATCH"),
                &json!([taken])
            ),
            (&json!("CREATED"), &null, &null),
        ]
    );
    let message = |n: usize| results[n]["error"]["message"].as_str().unwrap();
    assert!(message(3).contains("merge") && message(3).contains(&one) && message(3).contains(&two));
    assert!(message(4).contains(&holder), "{}", message(4));
    assert!(message(5).contains("zz:00:00:00:00:01"), "{}", message(5));
    assert!(message(7).contains("10.0.0.999"), "{}", message(7));

    for asset in [
        "MERGE", "HELD", "BADMAC", "GROUP", "BADIP", "NOSITE", "MISMATCH",
    ] {
        assert_eq!(device_of_asset(&schema, asset), None, "{asset}");
    }
    for asset in ["HOLDER", "TAKEN", "A-1", "A-2"] {
        assert!(device_of_asset(&schema, asset).is_some(), "{asset}");
    }
    // The devices of the refused MAC rows are unchanged.
    let value = data(&schema, &detail(&one)).await;
    assert_eq!(value["daiDevice"]["assetId"], Value::Null);
}

#[tokio::test]
async fn a_fixed_ip_without_a_site_is_at_the_one_site_in_use() {
    let schema = TestSchema::new().await;
    // A single-site customer with no stored default site.
    sensor(&schema.store(), "a.example.com", CUSTOMER);
    let value = data(
        &schema,
        &import(CUSTOMER, &[row("P-1", &[], &[(None, "10.0.0.50")], "", "")]),
    )
    .await;
    let device = results(&value)[0]["deviceId"].as_str().unwrap().to_string();
    let site = default_site(&schema.store(), CUSTOMER);
    assert_eq!(
        data(&schema, &detail(&device)).await["daiDevice"]["fixedIps"],
        json!([{ "site": site, "ip": "10.0.0.50" }])
    );

    // A multi-site customer has no one site.
    {
        let store = schema.store();
        let b = sensor(&store, "b.example.com", CUSTOMER);
        store.create_dai_site(CUSTOMER, "North", &[b]).unwrap();
    }
    let value = data(
        &schema,
        &import(
            CUSTOMER,
            &[
                row("P-2", &[], &[(None, "10.0.0.51")], "", ""),
                row("P-3", &[], &[(Some(&site), "10.0.0.52")], "", ""),
            ],
        ),
    )
    .await;
    assert_eq!(
        results(&value)[0]["error"]["reason"],
        json!("SITE_REQUIRED")
    );
    assert_eq!(results(&value)[1]["outcome"], json!("CREATED"));
    assert_eq!(device_of_asset(&schema, "P-2"), None);
}

#[tokio::test]
async fn more_than_10000_rows_are_refused_whole() {
    let schema = TestSchema::new().await;
    let rows: Vec<String> = (0..=10_000)
        .map(|n| format!(r#"{{ assetId: "R-{n}", macs: [], fixedIps: [] }}"#))
        .collect();
    let error = refused(&schema, &import(OTHER, &rows)).await;
    assert!(error.message.contains("10001"), "{}", error.message);
    let found = schema
        .store()
        .dai_search(OTHER, "R-0", super::wall_clock())
        .unwrap();
    assert_eq!(found.matches, Vec::new());
}

fn merge(survivor: &str, others: &[&str]) -> String {
    format!(
        r#"mutation {{ mergeDaiDevices(customerId: "{CUSTOMER}", survivor: "{survivor}", others: {others:?}) }}"#
    )
}

#[tokio::test]
async fn a_merge_leaves_the_survivor_with_everything_and_the_others_as_aliases() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let ids: Vec<String> = {
        let store = schema.store();
        agent.send(
            &store,
            (1..=4)
                .map(|n| ack(t(1), &format!("10.0.0.{n}"), n))
                .collect(),
        );
        agent.reach(&store, &[Kind::DhcpLease], t(10));
        apply_all(&store);
        (1..=4).map(|n| device_of_mac(&store, n)).collect()
    };

    assert_eq!(
        data(&schema, &merge(&ids[0], &[&ids[1]])).await,
        json!({ "mergeDaiDevices": ids[0] })
    );
    let value = data(&schema, &detail(&ids[1])).await;
    let device = &value["daiDevice"];
    assert_eq!(device["deviceId"], json!(ids[0]));
    let identifiers = device["identifiers"].as_array().unwrap();
    assert!(identifiers.contains(&json!({ "kind": "MAC", "value": mac_text(1) })));
    assert!(identifiers.contains(&json!({ "kind": "MAC", "value": mac_text(2) })));
    let addresses: Vec<&Value> = device["ipHistory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|binding| &binding["ip"])
        .collect();
    assert!(addresses.contains(&&json!("10.0.0.1")) && addresses.contains(&&json!("10.0.0.2")));
    let value = data_at(
        &schema,
        &format!(
            r#"{{ daiResolve(customerId: "{CUSTOMER}", items: [{{ site: "{site}", ip: "10.0.0.2", at: "{}" }}]) {{
                ... on DaiResolveAnswer {{ subjectId }}
            }} }}"#,
            rfc3339(t(5))
        ),
        t(20),
    )
    .await;
    assert_eq!(
        value["daiResolve"][0]["subjectId"],
        json!(format!("dev:{}", ids[0]))
    );

    // The survivor into itself.
    let error = refused(&schema, &merge(&ids[0], &[&ids[1]])).await;
    assert!(error.message.contains("survivor"), "{}", error.message);
    // Devices of different asset ids.
    data(
        &schema,
        &import(
            CUSTOMER,
            &[
                row("X", &[&mac_text(3)], &[], "", ""),
                row("Y", &[&mac_text(4)], &[], "", ""),
            ],
        ),
    )
    .await;
    let error = refused(&schema, &merge(&ids[2], &[&ids[3]])).await;
    assert!(error.message.contains("asset id"), "{}", error.message);
    assert_eq!(
        data(&schema, &detail(&ids[3])).await["daiDevice"]["deviceId"],
        json!(ids[3])
    );
}

fn split(device: &str, identifiers: &[(&str, &str)]) -> String {
    let identifiers = identifiers
        .iter()
        .map(|(kind, value)| format!(r#"{{ kind: {kind}, value: "{value}" }}"#))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"mutation {{ splitDaiDevice(customerId: "{CUSTOMER}", deviceId: "{device}", identifiers: [{identifiers}]) }}"#
    )
}

#[tokio::test]
async fn a_split_moves_exactly_the_chosen_identifiers_and_their_bindings() {
    let schema = TestSchema::new().await;
    let (mut agent, _) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    data(
        &schema,
        &import(
            CUSTOMER,
            &[row("S-1", &[&mac_text(5), &mac_text(6)], &[], "", "")],
        ),
    )
    .await;
    let device = {
        let store = schema.store();
        agent.send(
            &store,
            vec![ack(t(1), "10.0.0.5", 5), ack(t(1), "10.0.0.6", 6)],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(10));
        apply_all(&store);
        device_of_mac(&store, 5)
    };
    let stored = data(&schema, &detail(&device)).await;

    for (identifiers, cause) in [
        (vec![], "at least one"),
        (
            vec![
                ("MAC", mac_text(5)),
                ("MAC", mac_text(6)),
                ("OPERATOR_ASSET_ID", "S-1".to_string()),
            ],
            "every identifier",
        ),
        (vec![("MAC", mac_text(7))], "not on the device"),
    ] {
        let identifiers: Vec<(&str, &str)> = identifiers
            .iter()
            .map(|(kind, value)| (*kind, value.as_str()))
            .collect();
        let error = refused(&schema, &split(&device, &identifiers)).await;
        assert!(error.message.contains(cause), "{}", error.message);
    }
    assert_eq!(data(&schema, &detail(&device)).await, stored);

    let value = data(&schema, &split(&device, &[("MAC", &mac_text(6))])).await;
    let new = value["splitDaiDevice"].as_str().unwrap().to_string();
    let value = data(&schema, &detail(&new)).await;
    assert_eq!(
        value["daiDevice"]["identifiers"],
        json!([{ "kind": "MAC", "value": mac_text(6) }])
    );
    assert_eq!(
        value["daiDevice"]["ipHistory"],
        json!([{ "ip": "10.0.0.6", "start": rfc3339(t(1)) }])
    );
    let value = data(&schema, &detail(&device)).await;
    let identifiers = value["daiDevice"]["identifiers"].as_array().unwrap();
    assert_eq!(identifiers.len(), 2);
    assert!(identifiers.contains(&json!({ "kind": "MAC", "value": mac_text(5) })));
    assert_eq!(
        value["daiDevice"]["ipHistory"],
        json!([{ "ip": "10.0.0.5", "start": rfc3339(t(1)) }])
    );
}

fn states(devices: &[&str], fields: &str) -> String {
    format!(
        r#"mutation {{ setDaiDeviceStates(customerId: "{CUSTOMER}", deviceIds: {devices:?}{fields}) }}"#
    )
}

#[tokio::test]
async fn a_state_change_writes_one_entry_per_changed_device_and_no_answer_changes() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let ids: Vec<String> = {
        let store = schema.store();
        agent.send(
            &store,
            (1..=3)
                .map(|n| ack(t(1), &format!("10.0.0.{n}"), n))
                .collect(),
        );
        agent.reach(&store, &[Kind::DhcpLease], t(10));
        apply_all(&store);
        (1..=3).map(|n| device_of_mac(&store, n)).collect()
    };
    let resolve = format!(
        r#"{{ daiResolve(customerId: "{CUSTOMER}", items: [
            {{ site: "{site}", ip: "10.0.0.1", at: "{0}" }},
            {{ site: "{site}", ip: "10.0.0.3", at: "{0}" }}
        ]) {{ ... on DaiResolveAnswer {{ kind subjectId evidenceSources }} }} }}"#,
        rfc3339(t(5))
    );
    let answered = data_at(&schema, &resolve, t(20)).await;
    data(&schema, &states(&[&ids[2]], ", verdict: CONFIRMED")).await;
    let changes = |value: &Value| value["daiDevice"]["changes"].as_array().unwrap().len();
    let mut before = Vec::new();
    for id in &ids {
        before.push(changes(&data(&schema, &detail(id)).await));
    }

    assert_eq!(
        data(
            &schema,
            &states(&[&ids[0], &ids[1], &ids[2]], ", verdict: CONFIRMED")
        )
        .await,
        json!({ "setDaiDeviceStates": true })
    );
    let mut after = Vec::new();
    for id in &ids {
        let value = data(&schema, &detail(id)).await;
        assert_eq!(value["daiDevice"]["verdict"], json!("CONFIRMED"));
        after.push(changes(&value));
    }
    assert_eq!(after, [before[0] + 1, before[1] + 1, before[2]]);
    assert_eq!(data_at(&schema, &resolve, t(20)).await, answered);

    data(&schema, &states(&[&ids[0]], ", activity: HIDDEN")).await;
    assert_eq!(
        data(&schema, &detail(&ids[0])).await["daiDevice"]["activity"],
        json!("HIDDEN")
    );
    assert_eq!(data_at(&schema, &resolve, t(20)).await, answered);

    // Refusals change nothing.
    let stored = data(&schema, &detail(&ids[1])).await;
    for (mutation, cause) in [
        (states(&[&ids[1]], ", activity: NOT_SEEN"), "NOT_SEEN"),
        (states(&[&ids[1]], ""), "at least one"),
        (
            states(
                &[&ids[1], "00000000-0000-4000-8000-000000000000"],
                ", verdict: IGNORED",
            ),
            "00000000-0000-4000-8000-000000000000",
        ),
        (
            states(&[&ids[1], "printer"], ", verdict: IGNORED"),
            "printer",
        ),
    ] {
        let error = refused(&schema, &mutation).await;
        assert!(error.message.contains(cause), "{}", error.message);
    }
    assert_eq!(data(&schema, &detail(&ids[1])).await, stored);
}

#[tokio::test]
async fn a_removed_service_stays_flagged_and_the_version_stays() {
    let schema = TestSchema::new().await;
    let (mut agent, _) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let device = {
        let store = schema.store();
        agent.send(
            &store,
            vec![ack(t(1), "10.0.0.1", 1), service(t(2), "10.0.0.1", 22)],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(10));
        apply_all(&store);
        device_of_mac(&store, 1)
    };
    let version = data(&schema, &detail(&device)).await["daiDevice"]["version"].clone();
    let remove = |port: u16| {
        format!(
            r#"mutation {{ removeDaiService(customerId: "{CUSTOMER}", deviceId: "{device}", port: {port}, protocol: 6) }}"#
        )
    };
    assert_eq!(
        data(&schema, &remove(22)).await,
        json!({ "removeDaiService": true })
    );
    let value = data(&schema, &detail(&device)).await;
    assert_eq!(
        value["daiDevice"]["services"],
        json!([{ "port": 22, "protocol": 6, "removed": true }])
    );
    assert_eq!(value["daiDevice"]["version"], version);

    let error = refused(&schema, &remove(80)).await;
    assert!(error.message.contains("80"), "{}", error.message);
}
