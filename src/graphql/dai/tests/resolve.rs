//! Point-in-time resolve.

use review_database::{DaiImportOutcome, DaiImportRow, DaiSearchTarget, Store, event::NetworkType};
use review_protocol::types::DaiObservationKind as Kind;
use serde_json::{Value, json};

use super::{
    Agent, CUSTOMER, MINUTE, OTHER, ack, apply_all, data_at, default_site, enable, ip, kerberos,
    mac, mac_text, ntlm, refused, rfc3339, sensor, wall_clock,
};
use crate::graphql::TestSchema;
use crate::graphql::time_series_generation_test_support::{
    insert_internal_network, store_networks,
};

const ANSWER: &str = "__typename
    ... on DaiResolveAnswer {
        kind subjectId site deviceIds evidenceSources
        explanation {
            bindings { deviceId start end endEstimated evidenceKind evidence { kind time sensor } }
            gapCauses {
                __typename
                ... on DaiAfterComparedTime { sensor value kind time }
                ... on DaiSkippedByCatchup { sensor kind start end }
            }
        }
    }
    ... on DaiResolveItemError { code message }";

fn resolve(customer: u32, items: &[String], explain: bool) -> String {
    format!(
        r#"{{ daiResolve(customerId: "{customer}", items: [{}], withExplanation: {explain}) {{ {ANSWER} }} }}"#,
        items.join(", ")
    )
}

fn at(addr: &str, time: i64) -> String {
    format!(r#"{{ ip: "{addr}", at: "{}" }}"#, rfc3339(time))
}

fn at_site(site: &str, addr: &str, time: i64) -> String {
    format!(
        r#"{{ site: "{site}", ip: "{addr}", at: "{}" }}"#,
        rfc3339(time)
    )
}

fn window(addr: &str, from: i64, to: i64) -> String {
    format!(
        r#"{{ ip: "{addr}", from: "{}", to: "{}" }}"#,
        rfc3339(from),
        rfc3339(to)
    )
}

/// Returns the answers of a `daiResolve` response.
fn answers(value: &Value) -> &Vec<Value> {
    value["daiResolve"].as_array().unwrap()
}

/// Returns the current id of the device holding MAC `n`.
fn device_of_mac(store: &Store, n: u8) -> String {
    let result = store
        .dai_search(CUSTOMER, &mac_text(n), wall_clock())
        .unwrap();
    match &result.matches.first().unwrap().target {
        DaiSearchTarget::Device(device) => device.to_string(),
        DaiSearchTarget::IpDevice { .. } => panic!("a MAC names a device"),
    }
}

/// Imports a device of `asset_id` holding `macs` with the fixed IP `addr`
/// at `site`, and returns its id.
fn fixed(store: &Store, asset_id: &str, macs: &[u8], site: &str, addr: &str) -> String {
    let outcome = store
        .import_dai_devices(
            CUSTOMER,
            &[DaiImportRow {
                asset_id: asset_id.to_string(),
                macs: macs.iter().map(|n| mac(*n)).collect(),
                fixed_ips: vec![(site.to_string(), ip(addr))],
                ..DaiImportRow::default()
            }],
        )
        .unwrap();
    match outcome.first().unwrap() {
        DaiImportOutcome::Created { device }
        | DaiImportOutcome::Attached { device }
        | DaiImportOutcome::Updated { device } => device.to_string(),
        DaiImportOutcome::Error(error) => panic!("{error}"),
    }
}

/// A customer with device identification on, one sensor in its default
/// site, `10.0.0.0/8` as its Intranet, and an agent whose first cursor read
/// opened the slot observations are timed from.
fn collecting(schema: &TestSchema) -> (Agent, String) {
    let store = schema.store();
    let a = sensor(&store, "a.example.com", CUSTOMER);
    insert_internal_network(&store, CUSTOMER);
    enable(&store, CUSTOMER);
    let site = default_site(&store, CUSTOMER);
    (Agent::start(&store, &a, CUSTOMER), site)
}

fn answer(kind: &str, subject: &str, site: &str, devices: &[&str], sources: &[&str]) -> Value {
    json!({
        "__typename": "DaiResolveAnswer",
        "kind": kind,
        "subjectId": subject,
        "site": site,
        "deviceIds": devices,
        "evidenceSources": sources,
        "explanation": null,
    })
}

#[tokio::test]
// One fixture, checked against every filter or kind in turn.
#[allow(clippy::too_many_lines)]
async fn each_kind_at_a_time_and_over_a_window() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let (mac1, mac2, mac3, mac4, mac5, printer, other_fixed) = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                ack(t(1), "10.0.0.1", 1),
                ack(t(1), "10.0.0.3", 2),
                ack(t(15), "10.0.0.3", 3),
                ack(t(1), "10.0.0.4", 4),
                ack(t(1), "10.0.0.5", 5),
            ],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(60));
        apply_all(&store);
        let printer = fixed(&store, "PRN-1", &[], &site, "10.0.0.2");
        let other_fixed = fixed(&store, "PRN-4", &[], &site, "10.0.0.4");
        // The device holding MAC 5 takes the asset id and the fixed IP.
        let same = fixed(&store, "PC-5", &[5], &site, "10.0.0.5");
        assert_eq!(same, device_of_mac(&store, 5));
        (
            device_of_mac(&store, 1),
            device_of_mac(&store, 2),
            device_of_mac(&store, 3),
            device_of_mac(&store, 4),
            same,
            printer,
            other_fixed,
        )
    };
    let dev = |id: &str| format!("dev:{id}");
    let mut two = [mac2.as_str(), mac3.as_str()];
    two.sort_unstable();
    let mut four = [mac4.as_str(), other_fixed.as_str()];
    four.sort_unstable();

    let items = [
        at("10.0.0.1", t(5)),
        // The binding has no stored end, but its last ACK plus twice the
        // lease time has passed.
        at("10.0.0.1", t(20)),
        at("10.0.0.2", t(5)),
        // The binding in effect wins over the fixed IP.
        at("10.0.0.4", t(5)),
        at("10.0.0.4", t(20)),
        window("10.0.0.3", t(0), t(30)),
        window("10.0.0.4", t(5), t(20)),
        window("10.0.0.5", t(5), t(20)),
        window("10.0.0.1", t(0), t(30)),
        at("10.0.0.9", t(5)),
    ];
    let value = data_at(&schema, &resolve(CUSTOMER, &items, false), t(61)).await;
    assert_eq!(
        answers(&value),
        &vec![
            answer("DEVICE", &dev(&mac1), &site, &[&mac1], &["DHCP_LEASE"]),
            answer("IP_SUBJECT", "ip:10.0.0.1", &site, &[], &[]),
            answer(
                "DEVICE",
                &dev(&printer),
                &site,
                &[&printer],
                &["OPERATOR_FIXED_IP"]
            ),
            answer("DEVICE", &dev(&mac4), &site, &[&mac4], &["DHCP_LEASE"]),
            answer(
                "DEVICE",
                &dev(&other_fixed),
                &site,
                &[&other_fixed],
                &["OPERATOR_FIXED_IP"]
            ),
            answer("AMBIGUOUS", "ip:10.0.0.3", &site, &two, &["DHCP_LEASE"]),
            answer(
                "AMBIGUOUS",
                "ip:10.0.0.4",
                &site,
                &four,
                &["DHCP_LEASE", "OPERATOR_FIXED_IP"]
            ),
            answer(
                "DEVICE",
                &dev(&mac5),
                &site,
                &[&mac5],
                &["DHCP_LEASE", "OPERATOR_FIXED_IP"]
            ),
            answer("DEVICE", &dev(&mac1), &site, &[&mac1], &["DHCP_LEASE"]),
            answer("IP_SUBJECT", "ip:10.0.0.9", &site, &[], &[]),
        ]
    );

    // The explanation names the deciding binding and its evidence.
    let value = data_at(
        &schema,
        &resolve(CUSTOMER, &[at("10.0.0.1", t(5))], true),
        t(61),
    )
    .await;
    assert_eq!(
        answers(&value)[0]["explanation"],
        json!({
            "bindings": [{
                "deviceId": mac1,
                "start": rfc3339(t(1)),
                "end": rfc3339(t(11)),
                "endEstimated": true,
                "evidenceKind": "DHCP_LEASE",
                "evidence": [{ "kind": "DHCP_LEASE", "time": rfc3339(t(1)), "sensor": agent.sensor }],
            }],
            "gapCauses": [],
        })
    );
}

#[tokio::test]
async fn item_errors_fail_only_their_item() {
    let schema = TestSchema::new().await;
    let (agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let ok = answer("IP_SUBJECT", "ip:10.0.0.9", &site, &[], &[]);
    let items = [
        at_site("nosuchst", "10.0.0.9", t(0)),
        at("10.0.0.9", t(0)),
        window("10.0.0.9", t(20), t(10)),
        at("10.0.0.999", t(0)),
        r#"{ ip: "10.0.0.9" }"#.to_string(),
        format!(
            r#"{{ ip: "10.0.0.9", at: "{0}", from: "{0}", to: "{0}" }}"#,
            rfc3339(t(0))
        ),
        format!(r#"{{ ip: "10.0.0.9", from: "{}" }}"#, rfc3339(t(0))),
        r#"{ ip: "10.0.0.9", at: "2300-01-01T00:00:00Z" }"#.to_string(),
        at_site(&site, "10.0.0.9", t(0)),
    ];
    let value = data_at(&schema, &resolve(CUSTOMER, &items, false), t(0)).await;
    let got = answers(&value);
    let codes: Vec<&Value> = got.iter().map(|answer| &answer["code"]).collect();
    assert_eq!(
        codes,
        [
            &json!("UNKNOWN_SITE"),
            &Value::Null,
            &json!("INVERTED_WINDOW"),
            &json!("INVALID_IP"),
            &json!("INVALID_TIME"),
            &json!("INVALID_TIME"),
            &json!("INVALID_TIME"),
            &json!("INVALID_TIME"),
            &Value::Null,
        ]
    );
    assert!(got[0]["message"].as_str().unwrap().contains("nosuchst"));
    assert!(got[3]["message"].as_str().unwrap().contains("10.0.0.999"));
    assert!(got[7]["message"].as_str().unwrap().contains("1677 to 2262"));
    // A site-less item of a customer that is not multi-site resolves at its
    // one site in use.
    let mut answered = got[1].clone();
    answered["kind"] = json!("IP_SUBJECT");
    assert_eq!(answered, ok);
    assert_eq!(got[1]["site"], json!(site));

    // A multi-site customer needs a site.
    {
        let store = schema.store();
        let b = sensor(&store, "b.example.com", CUSTOMER);
        store.create_dai_site(CUSTOMER, "North", &[b]).unwrap();
    }
    let value = data_at(
        &schema,
        &resolve(
            CUSTOMER,
            &[at("10.0.0.9", t(0)), at_site(&site, "10.0.0.9", t(0))],
            false,
        ),
        t(0),
    )
    .await;
    assert_eq!(answers(&value)[0]["code"], json!("SITE_REQUIRED"));
    assert_eq!(answers(&value)[1]["__typename"], json!("DaiResolveAnswer"));

    // A customer with no site at all has none to resolve at.
    let value = data_at(
        &schema,
        &resolve(OTHER, &[at("10.0.0.9", t(0))], false),
        t(0),
    )
    .await;
    assert_eq!(answers(&value)[0]["code"], json!("NO_SITE"));
}

#[tokio::test]
async fn more_than_1000_items_refuse_the_whole_call() {
    let schema = TestSchema::new().await;
    let (agent, site) = collecting(&schema);
    let item = at_site(&site, "10.0.0.9", agent.at(0));
    let value = data_at(
        &schema,
        &resolve(CUSTOMER, &vec![item.clone(); 1000], false),
        agent.at(0),
    )
    .await;
    assert_eq!(answers(&value).len(), 1000);
    // An invalid item counts too.
    let mut items = vec![item; 1000];
    items.push(at("not an address", agent.at(0)));
    let error = refused(&schema, &resolve(CUSTOMER, &items, false)).await;
    assert!(error.message.contains("1001"), "{}", error.message);
}

#[tokio::test]
async fn the_ip_subject_names_the_site_only_where_the_ip_is_ambiguous_across_sites() {
    let schema = TestSchema::new().await;
    let (agent, site) = collecting(&schema);
    let now = agent.at(0);
    let subject = |value: &Value| answers(value)[0]["subjectId"].clone();
    let query = |addr: &str| resolve(CUSTOMER, &[at_site(&site, addr, now)], false);

    // One site in use.
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!("ip:10.0.0.9"));

    // Multi-site, the setting on, an Intranet or Gateway address.
    {
        let store = schema.store();
        let b = sensor(&store, "b.example.com", CUSTOMER);
        store.create_dai_site(CUSTOMER, "North", &[b]).unwrap();
    }
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!(format!("ip:{site}/10.0.0.9")));
    let value = data_at(&schema, &query("192.168.0.9"), now).await;
    assert_eq!(subject(&value), json!("ip:192.168.0.9"));
    let value = data_at(&schema, &query("2001:DB8:0:0::1"), now).await;
    assert_eq!(subject(&value), json!("ip:2001:db8::1"));
    store_networks(&schema.store(), CUSTOMER, NetworkType::Gateway);
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!(format!("ip:{site}/10.0.0.9")));
    store_networks(&schema.store(), CUSTOMER, NetworkType::Extranet);
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!("ip:10.0.0.9"));

    // The setting off.
    store_networks(&schema.store(), CUSTOMER, NetworkType::Intranet);
    set_enabled(&schema.store(), false);
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!("ip:10.0.0.9"));
    set_enabled(&schema.store(), true);
    let value = data_at(&schema, &query("10.0.0.9"), now).await;
    assert_eq!(subject(&value), json!(format!("ip:{site}/10.0.0.9")));
}

/// Turns device account identification of [`CUSTOMER`] on or off.
fn set_enabled(store: &Store, enabled: bool) {
    let stored = store.dai_settings(CUSTOMER).unwrap();
    store
        .set_dai_settings(
            CUSTOMER,
            stored.revision,
            &review_database::DaiSettingsUpdate {
                device_account_identification: enabled,
                inactivity_multiplier: stored.inactivity_multiplier,
                no_lease_inactivity_secs: stored.no_lease_inactivity_secs,
                evidence_aging_secs: stored.evidence_aging_secs,
                kerberos_preauth_realms: stored.kerberos_preauth_realms,
            },
        )
        .unwrap();
}

#[tokio::test]
async fn an_evidence_gap_keeps_the_subject_the_evidence_gives_and_names_its_cause() {
    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let (mac6, mac7, printer) = {
        let store = schema.store();
        agent.send(
            &store,
            vec![ack(t(1), "10.0.0.1", 1), ack(t(28), "10.0.0.7", 7)],
        );
        agent.reach(&store, &[Kind::DhcpLease], t(30));
        // The agent skips 10 minutes of DHCP.
        agent.skip(&store, Kind::DhcpLease, t(40));
        agent.send(&store, vec![ack(t(55), "10.0.0.6", 6)]);
        agent.reach(&store, &[Kind::DhcpLease], t(60));
        apply_all(&store);
        let printer = fixed(&store, "PRN-2", &[], &site, "10.0.0.2");
        (device_of_mac(&store, 6), device_of_mac(&store, 7), printer)
    };
    let sensor = agent.sensor.clone();
    let skipped = json!({
        "__typename": "DaiSkippedByCatchup",
        "sensor": sensor,
        "kind": "DHCP_LEASE",
        "start": rfc3339(t(30)),
        "end": rfc3339(t(40)),
    });

    let items = [
        // Beyond the evidence: a binding, a fixed IP and nothing selecting.
        at("10.0.0.6", t(62)),
        at("10.0.0.2", t(70)),
        at("10.0.0.9", t(70)),
        window("10.0.0.9", t(50), t(70)),
        // In the skipped range: nothing, and a binding opened before it.
        at("10.0.0.1", t(35)),
        at("10.0.0.7", t(32)),
        window("10.0.0.9", t(20), t(31)),
        // Neither.
        at("10.0.0.9", t(50)),
    ];
    let value = data_at(&schema, &resolve(CUSTOMER, &items, true), t(61)).await;
    let got = answers(&value);
    let kinds: Vec<(&Value, &Value)> = got
        .iter()
        .map(|answer| (&answer["kind"], &answer["subjectId"]))
        .collect();
    assert_eq!(
        kinds,
        [
            (&json!("EVIDENCE_GAP"), &json!(format!("dev:{mac6}"))),
            (&json!("EVIDENCE_GAP"), &json!(format!("dev:{printer}"))),
            (&json!("EVIDENCE_GAP"), &json!("ip:10.0.0.9")),
            (&json!("EVIDENCE_GAP"), &json!("ip:10.0.0.9")),
            (&json!("EVIDENCE_GAP"), &json!("ip:10.0.0.1")),
            (&json!("EVIDENCE_GAP"), &json!(format!("dev:{mac7}"))),
            (&json!("EVIDENCE_GAP"), &json!("ip:10.0.0.9")),
            (&json!("IP_SUBJECT"), &json!("ip:10.0.0.9")),
        ]
    );
    assert_eq!(got[1]["evidenceSources"], json!(["OPERATOR_FIXED_IP"]));

    // The cause beyond the evidence is the site's compared time.
    let causes = got[0]["explanation"]["gapCauses"].as_array().unwrap();
    assert_eq!(causes.len(), 1, "{causes:?}");
    assert_eq!(causes[0]["__typename"], json!("DaiAfterComparedTime"));
    assert_eq!(causes[0]["sensor"], json!(sensor));
    assert_eq!(causes[0]["time"], json!(rfc3339(t(60))));
    assert!(
        [json!("CURSOR"), json!("LAST_RECORD_TIME")].contains(&causes[0]["value"]),
        "{causes:?}"
    );
    assert_eq!(
        got[0]["explanation"]["bindings"][0]["deviceId"],
        json!(mac6)
    );
    // The cause in the skipped range is the skipped range.
    assert_eq!(got[4]["explanation"]["gapCauses"], json!([skipped]));
    assert_eq!(got[5]["explanation"]["gapCauses"], json!([skipped]));
    assert_eq!(got[7]["explanation"]["gapCauses"], json!([]));

    // With no device selected, the subject is the one its conditions give.
    {
        let store = schema.store();
        let b = sensor_of(&store, "b.example.com");
        store.create_dai_site(CUSTOMER, "North", &[b]).unwrap();
    }
    let value = data_at(
        &schema,
        &resolve(CUSTOMER, &[at_site(&site, "10.0.0.9", t(70))], false),
        t(61),
    )
    .await;
    assert_eq!(answers(&value)[0]["kind"], json!("EVIDENCE_GAP"));
    assert_eq!(
        answers(&value)[0]["subjectId"],
        json!(format!("ip:{site}/10.0.0.9"))
    );
}

fn sensor_of(store: &Store, host: &str) -> String {
    sensor(store, host, CUSTOMER)
}

/// No answer carries a user name, an account name or a realm a Kerberos or
/// an NTLM observation saw; a machine account is a device identifier only.
#[tokio::test]
async fn no_answer_carries_an_account_of_an_observation() {
    const SECRETS: [&str; 6] = [
        "alice",
        "bob",
        "secretdom",
        "ws-secret",
        "corp.example",
        "ws01$",
    ];

    let schema = TestSchema::new().await;
    let (mut agent, site) = collecting(&schema);
    let start = agent.start;
    let t = |minutes: i64| start + minutes * MINUTE;
    let device = {
        let store = schema.store();
        agent.send(
            &store,
            vec![
                ack(t(1), "10.0.0.1", 1),
                kerberos(t(2), "10.0.0.1", "WS01$", "corp.example"),
                kerberos(t(3), "10.0.0.1", "alice", "corp.example"),
                ntlm(t(4), "10.0.0.1", "bob", "SECRETDOM", "WS-SECRET"),
            ],
        );
        agent.reach(
            &store,
            &[Kind::DhcpLease, Kind::Kerberos, Kind::Ntlm],
            t(60),
        );
        apply_all(&store);
        device_of_mac(&store, 1)
    };
    let assert_clean = |value: &Value| {
        let text = value.to_string().to_ascii_lowercase();
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    };

    for explain in [false, true] {
        let items = [
            at("10.0.0.1", t(3)),
            at_site(&site, "10.0.0.1", t(4)),
            window("10.0.0.1", t(0), t(10)),
        ];
        let value = data_at(&schema, &resolve(CUSTOMER, &items, explain), t(61)).await;
        assert_eq!(
            answers(&value)[0]["subjectId"],
            json!(format!("dev:{device}"))
        );
        assert_clean(&value);
    }

    let query = format!(
        r#"{{ daiDevice(customerId: "{CUSTOMER}", deviceId: "{device}") {{
            requestedId deviceId aliasFollowed identifiers {{ kind value lastConfirmed }}
            names {{ value source lastSeen }} representativeName wasDhcpServer verdict activity
            origin assetId memo version firstSeen lastSeen fixedIps {{ site ip }}
            ipHistory {{ site ip start end endEstimated evidenceKind }}
            services {{ port protocol externalClient firstSeen lastSeen removed notSeen }}
            software {{ side source text firstSeen lastSeen }}
            changes {{ version kind relatedDeviceId fields {{ path op before after }} time source observationKind }}
            aliases {{ deviceId time reason }}
        }} }}"#
    );
    let mut value = data_at(&schema, &query, t(61)).await;
    let detail = value["daiDevice"].as_object_mut().unwrap();
    let identifiers = detail.remove("identifiers").unwrap();
    assert!(
        identifiers
            .as_array()
            .unwrap()
            .iter()
            .any(|identifier| identifier["kind"] == "MACHINE_ACCOUNT"
                && identifier["value"] == "WS01$@CORP.EXAMPLE"),
        "{identifiers}"
    );
    // The change history adds the identifier, as an identifier.
    for change in detail["changes"].as_array_mut().unwrap() {
        change["fields"]
            .as_array_mut()
            .unwrap()
            .retain(|field| field["path"] != "identifiers");
    }
    assert_clean(&value);
}
