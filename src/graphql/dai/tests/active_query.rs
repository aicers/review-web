//! Active query settings, display-only results and the packet send boundary.

use std::sync::Arc;
use std::task::Poll;

use futures::{FutureExt, poll};
use review_database::{
    DaiActiveQueryMdns, DaiActiveQueryNbns, DaiActiveQueryResult as R, DaiActiveQueryRound,
    DaiActiveQuerySsdp, Role,
};
use serde_json::{Value, json};

use super::super::active_query::SitesReadPause;
use super::devices::collecting;
use super::{
    CUSTOMER, DAY, MINUTE, OTHER, activity, apply_all, code, data, data_at, default_site,
    extension, ip, refused, rfc3339, run_as,
};
use crate::graphql::TestSchema;
use crate::graphql::customer_deletion_guard::test_support::{assert_locked, put_running_job};
use crate::graphql::time_series_generation_test_support::insert_internal_network;

const SETTINGS: &str = "customerId enabled excludedRanges revision";
const SITE: &str = "token queryRanges dnsServers rate revision";
const ANSWER: &str = "kind firstSeen lastSeen value { __typename
    ... on DaiActiveQueryPtr { names }
    ... on DaiActiveQueryNbns { computerName workgroupOrDomain mac }
    ... on DaiActiveQueryMdns { hostName serviceTypes }
    ... on DaiActiveQuerySsdpResponses { responses { st usn server } }
    ... on DaiActiveQueryNoName { kind }
    ... on DaiActiveQueryNoResponse { kind }
}";

fn settings(customer: u32, revision: u64, enabled: bool, ranges: &str) -> String {
    format!(
        r#"mutation {{ updateDaiActiveQuerySettings(customerId: "{customer}", revision: "{revision}", input: {{ enabled: {enabled}, excludedRanges: {ranges} }}) {{ {SETTINGS} }} }}"#
    )
}

fn site(customer: u32, token: &str, revision: u64, ranges: &str, dns: &str, rate: i32) -> String {
    format!(
        r#"mutation {{ updateDaiActiveQuerySite(customerId: "{customer}", token: {token}, revision: "{revision}", input: {{ queryRanges: {ranges}, dnsServers: {dns}, rate: {rate} }}) {{ {SITE} }} }}"#
    )
}

fn queries(customer: u32) -> Vec<String> {
    vec![
        format!(r#"{{ daiActiveQuerySettings(customerIds: ["{customer}"]) {{ {SETTINGS} }} }}"#),
        format!(r#"{{ daiActiveQuerySites(customerId: "{customer}") {{ {SITE} }} }}"#),
        format!(
            r#"{{ daiActiveAnswers(customerId: "{customer}", site: "removed", ip: "10.0.0.1") {{ {ANSWER} }} }}"#
        ),
        format!(
            r#"{{ daiIpOnlyDevices(customerId: "{customer}") {{ edges {{ node {{ activeQuery {{ status lastQuery kinds {{ kind lastResult answer {{ {ANSWER} }} }} }} }} }} }} }}"#
        ),
        format!(
            r#"{{ daiCollectionStatus(customerId: "{customer}") {{ sites {{ activeQuery {{ state noDnsServers lastQuery waitingIps waitingIpsOverLimit kinds {{ kind sentToday answeredToday sentLast30Days answeredLast30Days }} }} }} }} }}"#
        ),
        format!(
            r#"{{ daiResolve(customerId: "{customer}", withExplanation: true, items: [{{ ip: "10.0.0.1", at: "2026-11-27T00:00:00Z" }}]) {{ ... on DaiResolveAnswer {{ explanation {{ activeAnswers {{ {ANSWER} }} }} }} }} }}"#
        ),
    ]
}

#[tokio::test]
async fn roles_scope_and_deletion_guards() {
    let schema = TestSchema::new().await;
    for role in [
        Role::SystemAdministrator,
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ] {
        for query in queries(CUSTOMER) {
            let res = run_as(&schema, &query, role, &[CUSTOMER]).await;
            assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
            if role != Role::SystemAdministrator {
                let res = run_as(&schema, &query, role, &[OTHER]).await;
                assert_eq!(res.errors.first().unwrap().message, "Forbidden");
            }
        }
        let revision = schema
            .store()
            .dai_active_query_settings(CUSTOMER)
            .unwrap()
            .revision;
        for (mutation, allowed) in [
            (
                settings(CUSTOMER, revision, true, "[]"),
                matches!(
                    role,
                    Role::SystemAdministrator | Role::SecurityAdministrator
                ),
            ),
            (
                site(CUSTOMER, "null", 0, "[]", "[]", 20),
                role == Role::SystemAdministrator,
            ),
        ] {
            let res = run_as(&schema, &mutation, role, &[CUSTOMER]).await;
            assert_eq!(
                res.errors.iter().any(|e| e.message == "Forbidden"),
                !allowed,
                "{role:?}: {:?}",
                res.errors
            );
            if allowed {
                assert!(res.errors.is_empty(), "{role:?}: {:?}", res.errors);
            }
            if role != Role::SystemAdministrator {
                let res = run_as(&schema, &mutation, role, &[OTHER]).await;
                assert_eq!(res.errors.first().unwrap().message, "Forbidden");
            }
        }
    }
    let res = run_as(
        &schema,
        &format!(
            r#"{{ daiActiveQuerySettings(customerIds: ["{OTHER}", "{CUSTOMER}"]) {{ revision }} }}"#
        ),
        Role::SecurityMonitor,
        &[OTHER],
    )
    .await;
    assert_eq!(res.errors.first().unwrap().message, "Forbidden");
    assert!(res.data.into_json().unwrap().is_null());

    put_running_job(&schema.store(), CUSTOMER, &[]);
    for mutation in [
        settings(CUSTOMER, 0, false, "[]"),
        site(CUSTOMER, "null", 0, "[]", "[]", 20),
    ] {
        assert_locked(&schema.execute_as_system_admin(&mutation).await);
    }
}

#[tokio::test]
async fn defaults_default_site_writes_and_revision_refusals() {
    let schema = TestSchema::new().await;
    let value = data(&schema, &format!(r#"{{ daiActiveQuerySettings(customerIds: ["{OTHER}", "{CUSTOMER}"]) {{ {SETTINGS} }} daiActiveQuerySites(customerId: "{CUSTOMER}") {{ {SITE} }} }}"#)).await;
    assert_eq!(
        value["daiActiveQuerySettings"],
        json!([
            {"customerId": OTHER.to_string(), "enabled": false, "excludedRanges": [], "revision": "0"},
            {"customerId": CUSTOMER.to_string(), "enabled": false, "excludedRanges": [], "revision": "0"}
        ])
    );
    assert_eq!(
        value["daiActiveQuerySites"],
        json!([{"token": null, "queryRanges": [], "dnsServers": [], "rate": 20, "revision": "0"}])
    );
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), Vec::new());
    data(
        &schema,
        &settings(CUSTOMER, 0, true, r#"["10.1.2.3/16", "10.1.0.0/16"]"#),
    )
    .await;
    assert_eq!(
        schema
            .store()
            .dai_active_query_settings(CUSTOMER)
            .unwrap()
            .excluded_ranges,
        vec!["10.1.0.0/16".parse().unwrap()]
    );
    let first = data(
        &schema,
        &site(
            CUSTOMER,
            "null",
            0,
            r#"["10.0.0.1/24"]"#,
            r#"["10.0.0.2", "10.0.0.2"]"#,
            25,
        ),
    )
    .await;
    let token = default_site(&schema.store(), CUSTOMER);
    assert_eq!(
        first["updateDaiActiveQuerySite"],
        json!({"token": token, "queryRanges": ["10.0.0.0/24"], "dnsServers": ["10.0.0.2"], "rate": 25, "revision": "1"})
    );
    let second = data(&schema, &site(CUSTOMER, "null", 1, "[]", "[]", 20)).await;
    assert_eq!(second["updateDaiActiveQuerySite"]["token"], json!(token));
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap().len(), 1);
    let empty = refused(&schema, &site(CUSTOMER, r#""""#, 0, "[]", "[]", 20)).await;
    assert!(empty.message.contains("site not found"));
    for (mutation, stored) in [
        (settings(CUSTOMER, 0, false, "[]"), "1"),
        (site(CUSTOMER, "null", 0, "[]", "[]", 20), "2"),
    ] {
        let error = refused(&schema, &mutation).await;
        assert_eq!(code(&error).as_deref(), Some("STALE_REVISION"));
        assert_eq!(extension(&error, "storedRevision"), json!(stored));
    }
    let other = schema
        .store()
        .create_dai_site(CUSTOMER, "other", &[])
        .unwrap();
    let listed = data(&schema, &queries(CUSTOMER)[1]).await;
    let stored = schema.store().dai_active_query_sites(CUSTOMER).unwrap();
    assert_eq!(
        listed["daiActiveQuerySites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["token"].as_str().unwrap())
            .collect::<Vec<_>>(),
        stored.iter().map(|s| s.token.as_str()).collect::<Vec<_>>()
    );
    assert!(listed["daiActiveQuerySites"].as_array().unwrap().iter().any(|s| s == &json!({"token": other, "queryRanges": [], "dnsServers": [], "rate": 20, "revision": "0"})));

    // A failed write still leaves the newly ensured default site behind.
    let fresh = TestSchema::new().await;
    refused(&fresh, &site(CUSTOMER, "null", 1, "[]", "[]", 20)).await;
    assert_eq!(fresh.store().dai_sites(CUSTOMER).unwrap().len(), 1);
}

/// Returns a listed site entry with the values of a site without settings.
fn unconfigured(token: Option<&str>) -> Value {
    json!({"token": token, "queryRanges": [], "dnsServers": [], "rate": 20, "revision": "0"})
}

#[tokio::test]
async fn sites_list_the_default_site_once_without_concurrent_writes() {
    let schema = TestSchema::new().await;
    let listed = data(&schema, &queries(CUSTOMER)[1]).await;
    assert_eq!(listed["daiActiveQuerySites"], json!([unconfigured(None)]));
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), Vec::new());

    let default = schema.store().ensure_default_site(CUSTOMER).unwrap();
    let listed = data(&schema, &queries(CUSTOMER)[1]).await;
    assert_eq!(
        listed["daiActiveQuerySites"],
        json!([unconfigured(Some(&default))])
    );

    let other = schema
        .store()
        .create_dai_site(CUSTOMER, "other", &[])
        .unwrap();
    let mut tokens = [default.as_str(), other.as_str()];
    tokens.sort_unstable();
    let listed = data(&schema, &queries(CUSTOMER)[1]).await;
    assert_eq!(
        listed["daiActiveQuerySites"],
        json!(tokens.map(|token| unconfigured(Some(token))))
    );
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap().len(), 2);
}

/// The default site is created by `updateDaiActiveQuerySite(token: null)`
/// after the query has read the store and before it answers, where the
/// stored list and the default site check used to be two reads.
#[tokio::test]
async fn a_default_site_created_while_listing_is_listed_once() {
    let schema = TestSchema::new().await;
    let pause = Arc::new(SitesReadPause::default());
    let list = &queries(CUSTOMER)[1];
    let query = schema.execute_as_system_admin_with_data(list, Arc::clone(&pause));
    tokio::pin!(query);
    tokio::select! {
        biased;
        response = &mut query => {
            panic!("the query answered without pausing: {:?}", response.errors);
        }
        () = pause.reached() => {}
    }
    let written = data(&schema, &site(CUSTOMER, "null", 0, "[]", "[]", 20)).await;
    let token = default_site(&schema.store(), CUSTOMER);
    assert_eq!(written["updateDaiActiveQuerySite"]["token"], json!(token));
    pause.resume();
    let response = query.await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap()["daiActiveQuerySites"],
        json!([unconfigured(None)])
    );
    let listed = data(&schema, list).await;
    assert_eq!(
        listed["daiActiveQuerySites"],
        json!([{"token": token, "queryRanges": [], "dnsServers": [], "rate": 20, "revision": "1"}])
    );
}

#[tokio::test]
async fn parsing_and_overlap_reveal_only_the_ranges() {
    let schema = TestSchema::new().await;
    for (mutation, field) in [
        (settings(CUSTOMER, 0, false, r#"["bad"]"#), "excludedRanges"),
        (
            site(CUSTOMER, "null", 0, r#"["bad"]"#, "[]", 20),
            "queryRanges",
        ),
        (
            site(CUSTOMER, "null", 0, "[]", r#"["bad"]"#, 20),
            "dnsServers",
        ),
        (site(CUSTOMER, "null", 0, "[]", "[]", -1), "rate"),
        (
            r#"{ daiActiveAnswers(customerId: "1", site: "x", ip: "bad") { kind } }"#.to_owned(),
            "ip",
        ),
    ] {
        assert!(refused(&schema, &mutation).await.message.contains(field));
    }
    data(
        &schema,
        &site(CUSTOMER, "null", 0, r#"["10.0.0.0/24"]"#, "[]", 20),
    )
    .await;
    let error = refused(
        &schema,
        &site(OTHER, "null", 0, r#"["10.0.0.0/16"]"#, "[]", 20),
    )
    .await;
    assert_eq!(code(&error).as_deref(), Some("ACTIVE_QUERY_RANGES_OVERLAP"));
    assert_eq!(extension(&error, "ranges"), json!(["10.0.0.0/24"]));
    assert_eq!(
        serde_json::to_value(error.extensions.as_ref().unwrap())
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(error.message, "active query ranges overlap");
    let error = refused(&schema, &site(CUSTOMER, "null", 1, "[]", "[]", 0)).await;
    assert_eq!(error.message, "invalid active query setting: rate");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn stored_answers_map_every_union_member_and_existing_reads() {
    let schema = TestSchema::new().await;
    let (mut agent, token) = collecting(&schema);
    let time = agent.start + 20 * MINUTE;
    {
        let store = schema.store();
        insert_internal_network(&store, CUSTOMER);
        store
            .set_dai_active_query_settings(CUSTOMER, 0, true, &[])
            .unwrap();
        store
            .set_dai_active_query_site(
                CUSTOMER,
                &token,
                0,
                &["10.0.0.0/24".parse().unwrap()],
                &[ip("10.0.0.254")],
                20,
            )
            .unwrap();
        agent.send(
            &store,
            vec![activity(
                agent.start + MINUTE,
                agent.start + MINUTE,
                "10.0.0.1",
            )],
        );
        agent.reach(
            &store,
            &[review_protocol::types::DaiObservationKind::IpActivity],
            agent.start + 10 * MINUTE,
        );
        apply_all(&store);
    }
    let resolve = format!(
        r#"{{ daiResolve(customerId: "{CUSTOMER}", withExplanation: true, items: [{{ site: "{token}", ip: "10.0.0.1", at: "{}" }}]) {{ ... on DaiResolveAnswer {{ kind subjectId deviceIds evidenceSources explanation {{ activeAnswers {{ {ANSWER} }} }} }} }} }}"#,
        rfc3339(time + MINUTE)
    );
    let before = data_at(&schema, &resolve, time + MINUTE).await;
    assert_eq!(
        before["daiResolve"][0]["explanation"]["activeAnswers"],
        json!([])
    );
    let devices = r#"{ daiDevices(customerId: "1") { totalCount } }"#;
    assert_eq!(
        data_at(&schema, devices, time + MINUTE).await["daiDevices"]["totalCount"],
        "0"
    );
    {
        let store = schema.store();
        store
            .store_dai_active_round(
                CUSTOMER,
                &token,
                time,
                &[DaiActiveQueryRound {
                    ip: ip("10.0.0.1"),
                    ptr: R::Value(vec!["printer.example".into()]),
                    nbns: R::Value(DaiActiveQueryNbns {
                        computer_name: Some("PRINTER".into()),
                        workgroup_or_domain: None,
                        mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                    }),
                    mdns: R::Value(DaiActiveQueryMdns {
                        host_name: Some("printer.local".into()),
                        service_types: vec!["_ipp._tcp".into()],
                    }),
                    ssdp: R::Value(vec![DaiActiveQuerySsdp {
                        st: String::new(),
                        usn: "uuid:printer".into(),
                        server: "server".into(),
                    }]),
                }],
            )
            .unwrap();
    }
    let history = format!(
        r#"{{ daiActiveAnswers(customerId: "{CUSTOMER}", site: "{token}", ip: "10.0.0.1") {{ {ANSWER} }} }}"#
    );
    let value = data(&schema, &history).await;
    let answers = value["daiActiveAnswers"].as_array().unwrap();
    assert_eq!(
        answers
            .iter()
            .map(|a| a["kind"].clone())
            .collect::<Vec<_>>(),
        json!(["PTR", "NBNS", "MDNS", "SSDP"])
            .as_array()
            .unwrap()
            .clone()
    );
    assert_eq!(
        answers[0]["value"],
        json!({"__typename": "DaiActiveQueryPtr", "names": ["printer.example"]})
    );
    assert_eq!(
        answers[1]["value"],
        json!({"__typename": "DaiActiveQueryNbns", "computerName": "PRINTER", "workgroupOrDomain": null, "mac": "aa:bb:cc:dd:ee:ff"})
    );
    assert_eq!(
        answers[2]["value"],
        json!({"__typename": "DaiActiveQueryMdns", "hostName": "printer.local", "serviceTypes": ["_ipp._tcp"]})
    );
    assert_eq!(
        answers[3]["value"],
        json!({"__typename": "DaiActiveQuerySsdpResponses", "responses": [{"st": null, "usn": "uuid:printer", "server": "server"}]})
    );
    for answer in answers {
        assert_eq!(answer["firstSeen"], json!(rfc3339(time)));
        assert_eq!(answer["lastSeen"], json!(rfc3339(time)));
    }
    let rows = data_at(&schema, &queries(CUSTOMER)[3], time + MINUTE).await;
    let active = &rows["daiIpOnlyDevices"]["edges"][0]["node"]["activeQuery"];
    assert_eq!(active["status"], Value::Null);
    assert_eq!(active["lastQuery"], json!(rfc3339(time)));
    assert_eq!(active["kinds"].as_array().unwrap().len(), 4);
    assert!(
        active["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|k| k["lastResult"] == "VALUE" && !k["answer"].is_null())
    );
    let resolved = data_at(&schema, &resolve, time + MINUTE).await;
    for field in ["kind", "subjectId", "deviceIds", "evidenceSources"] {
        assert_eq!(
            resolved["daiResolve"][0][field],
            before["daiResolve"][0][field]
        );
    }
    assert_eq!(
        data_at(&schema, devices, time + MINUTE).await["daiDevices"]["totalCount"],
        "0"
    );
    assert_eq!(
        resolved["daiResolve"][0]["explanation"]["activeAnswers"],
        value["daiActiveAnswers"]
    );
    let search = data_at(&schema, r#"{ daiSearch(customerId: "1", text: "printer") { matches { matched target { __typename ... on DaiSearchIpDevice { ip site } } } } }"#, time + MINUTE).await;
    assert_eq!(
        search["daiSearch"]["matches"][0],
        json!({"matched": "ACTIVE_QUERY_NAME", "target": {"__typename": "DaiSearchIpDevice", "ip": "10.0.0.1", "site": token}})
    );
    let status = data_at(&schema, &queries(CUSTOMER)[4], time + MINUTE).await;
    let active = &status["daiCollectionStatus"]["sites"][0]["activeQuery"];
    assert_eq!(active["state"], "ON");
    assert_eq!(active["noDnsServers"], false);
    assert_eq!(active["waitingIps"], 0);
    assert_eq!(active["waitingIpsOverLimit"], false);
    for counts in active["kinds"].as_array().unwrap() {
        for field in [
            "sentToday",
            "answeredToday",
            "sentLast30Days",
            "answeredLast30Days",
        ] {
            assert_eq!(counts[field], "1");
        }
    }
    {
        let store = schema.store();
        store
            .store_dai_active_round(
                CUSTOMER,
                &token,
                time + DAY,
                &[DaiActiveQueryRound {
                    ip: ip("10.0.0.1"),
                    ptr: R::NoName,
                    nbns: R::NoResponse,
                    mdns: R::NotSent,
                    ssdp: R::NotSent,
                }],
            )
            .unwrap();
        store
            .set_dai_active_query_settings(CUSTOMER, 1, false, &[])
            .unwrap();
    }
    let value = data(&schema, &history).await;
    assert_eq!(
        value["daiActiveAnswers"][0]["value"],
        json!({"__typename": "DaiActiveQueryNoName", "kind": "PTR"})
    );
    assert_eq!(
        value["daiActiveAnswers"][1]["value"],
        json!({"__typename": "DaiActiveQueryNoResponse", "kind": "NBNS"})
    );
    let rows = data_at(&schema, &queries(CUSTOMER)[3], time + DAY + MINUTE).await;
    let active = &rows["daiIpOnlyDevices"]["edges"][0]["node"]["activeQuery"];
    assert_eq!(active["status"], "QUERIES_OFF");
    assert_eq!(active["kinds"][0]["lastResult"], "NO_NAME");
    assert_eq!(active["kinds"][1]["lastResult"], "NO_RESPONSE");
    assert_eq!(active["kinds"][2]["lastResult"], "NOT_SENT");
    assert_eq!(active["kinds"][3]["answer"], answers[3]);
    assert_eq!(
        data(
            &schema,
            r#"{ daiActiveAnswers(customerId: "1", site: "unknown", ip: "10.0.0.1") { kind } }"#
        )
        .await["daiActiveAnswers"],
        json!([])
    );
}

/// Polls a mutation until it is waiting, then checks storage while the send
/// read guard remains held. Polling the late reader proves the writer queued.
async fn blocked(schema: &TestSchema, mutation: &str, check: impl FnOnce()) -> Value {
    let guard = schema.active_query_send_gate.read().await;
    let response = schema.execute_as_system_admin(mutation).fuse();
    tokio::pin!(response);
    assert!(poll!(&mut response).is_pending(), "{mutation}");
    let late = schema.active_query_send_gate.read();
    tokio::pin!(late);
    assert!(
        poll!(&mut late).is_pending(),
        "writer did not queue: {mutation}"
    );
    assert!(
        schema.store.try_write().is_ok(),
        "store guard held while waiting: {mutation}"
    );
    check();
    drop(guard);
    let response = response.await;
    assert!(
        response.errors.is_empty(),
        "{mutation}: {:?}",
        response.errors
    );
    drop(late.await);
    response.data.into_json().unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn every_send_changing_mutation_waits_before_storing_and_responding() {
    let schema = TestSchema::new().await;
    blocked(&schema, &settings(CUSTOMER, 0, true, "[]"), || {
        assert_eq!(
            schema
                .store()
                .dai_active_query_settings(CUSTOMER)
                .unwrap()
                .revision,
            0
        );
    })
    .await;
    assert_eq!(
        schema
            .store()
            .dai_active_query_settings(CUSTOMER)
            .unwrap()
            .revision,
        1
    );
    blocked(&schema, &site(CUSTOMER, "null", 0, "[]", "[]", 20), || {
        assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), Vec::new());
    })
    .await;
    assert_eq!(
        schema.store().dai_active_query_sites(CUSTOMER).unwrap()[0].revision,
        1
    );
    blocked(&schema, r#"mutation { updateDaiCustomerSettings(customerId: "1", revision: "0", input: { deviceAccountIdentification: true, inactivityMultiplier: 2, noLeaseInactivitySecs: "3600", evidenceAgingSecs: "86400", kerberosPreauthRealms: [] }) { revision } }"#, || {
        assert_eq!(schema.store().dai_settings(CUSTOMER).unwrap().revision, 0);
    }).await;
    assert_eq!(schema.store().dai_settings(CUSTOMER).unwrap().revision, 1);
    let token = schema
        .store()
        .create_dai_site(CUSTOMER, "remove", &[])
        .unwrap();
    blocked(
        &schema,
        &format!(r#"mutation {{ removeDaiSite(customerId: "1", token: "{token}") }}"#),
        || {
            assert!(
                schema
                    .store()
                    .dai_sites(CUSTOMER)
                    .unwrap()
                    .iter()
                    .any(|s| s.token == token)
            );
        },
    )
    .await;
    assert!(
        !schema
            .store()
            .dai_sites(CUSTOMER)
            .unwrap()
            .iter()
            .any(|s| s.token == token)
    );
    blocked(
        &schema,
        r#"mutation { replaceCustomerNetworks(customerId: "1", revision: "1", networks: []) }"#,
        || {
            assert!(
                schema
                    .store()
                    .customer_networks_map()
                    .get(CUSTOMER)
                    .unwrap()
                    .is_none()
            );
        },
    )
    .await;
    assert!(
        schema
            .store()
            .customer_networks_map()
            .get(CUSTOMER)
            .unwrap()
            .is_some()
    );
    blocked(
        &schema,
        r#"mutation { removeCustomerNetworks(customerId: "1") }"#,
        || {
            assert!(
                schema
                    .store()
                    .customer_networks_map()
                    .get(CUSTOMER)
                    .unwrap()
                    .is_some()
            );
        },
    )
    .await;
    assert!(
        schema
            .store()
            .customer_networks_map()
            .get(CUSTOMER)
            .unwrap()
            .is_none()
    );
    data(&schema, "mutation { backup(numOfBackupsToKeep: 1) }").await;
    for restore in [
        "mutation { restoreFromLatestBackup }",
        r#"mutation { restoreFromBackup(id: "1") }"#,
    ] {
        let revision = schema
            .store()
            .dai_active_query_settings(CUSTOMER)
            .unwrap()
            .revision;
        data(&schema, &settings(CUSTOMER, revision, false, "[]")).await;
        blocked(&schema, restore, || {
            assert!(
                !schema
                    .store()
                    .dai_active_query_settings(CUSTOMER)
                    .unwrap()
                    .enabled
            );
        })
        .await;
        assert!(
            schema
                .store()
                .dai_active_query_settings(CUSTOMER)
                .unwrap()
                .enabled
        );
    }
}

#[tokio::test]
async fn deletion_does_not_wait_for_a_send_guard() {
    let schema = TestSchema::new().await;
    let _guard = schema.active_query_send_gate.read().await;
    let mut response = Box::pin(
        schema.execute_as_system_admin(r#"mutation { deleteCustomerData(customerId: "1") }"#),
    );
    match poll!(&mut response) {
        Poll::Ready(response) => assert!(response.errors.is_empty(), "{:?}", response.errors),
        Poll::Pending => panic!("deleteCustomerData waited for a send guard"),
    }
}

#[tokio::test]
async fn active_writes_take_the_dai_lock_before_the_send_gate() {
    let schema = TestSchema::new().await;
    for mutation in [
        settings(CUSTOMER, 0, true, "[]"),
        site(CUSTOMER, "null", 0, "[]", "[]", 20),
    ] {
        let dai = schema.hold_dai_writes_lock().await;
        let response = schema.execute_as_system_admin(&mutation);
        tokio::pin!(response);
        assert!(poll!(&mut response).is_pending());
        let send = schema
            .active_query_send_gate
            .write()
            .now_or_never()
            .expect("the gate is not held while waiting for the DAI writes lock");
        assert!(schema.store.try_write().is_ok());
        drop(send);
        drop(dai);
        assert_eq!(response.await.errors, Vec::new());
    }
}

#[tokio::test]
async fn history_is_read_even_after_removing_the_site() {
    let schema = TestSchema::new().await;
    let token = schema
        .store()
        .create_dai_site(CUSTOMER, "temporary", &[])
        .unwrap();
    {
        let store = schema.store();
        store
            .set_dai_active_query_site(
                CUSTOMER,
                &token,
                0,
                &["10.0.0.0/24".parse().unwrap()],
                &[],
                20,
            )
            .unwrap();
        store
            .store_dai_active_round(
                CUSTOMER,
                &token,
                1,
                &[DaiActiveQueryRound {
                    ip: ip("10.0.0.1"),
                    ptr: R::NoName,
                    nbns: R::NoResponse,
                    mdns: R::NotSent,
                    ssdp: R::NotSent,
                }],
            )
            .unwrap();
        store.remove_dai_site(CUSTOMER, &token).unwrap();
    }
    let value = data(&schema, &format!(r#"{{ daiActiveAnswers(customerId: "{CUSTOMER}", site: "{token}", ip: "10.0.0.1") {{ {ANSWER} }} }}"#)).await;
    assert_eq!(value["daiActiveAnswers"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["daiActiveAnswers"][0]["value"]["__typename"],
        "DaiActiveQueryNoName"
    );
}

#[tokio::test]
async fn a_not_sent_history_value_is_a_field_error() {
    use async_graphql::{EmptyMutation, EmptySubscription, Schema, SimpleObject};

    #[derive(SimpleObject)]
    struct Query {
        answer: super::super::active_query::DaiActiveAnswer<'static>,
    }
    let schema = Schema::build(
        Query {
            answer: review_database::DaiActiveAnswer {
                kind: review_database::DaiActiveQueryKind::Ptr,
                value: R::NotSent,
                first_seen: 1,
                last_seen: 1,
            }
            .into(),
        },
        EmptyMutation,
        EmptySubscription,
    )
    .finish();
    let res = schema.execute("{ answer { value { __typename } } }").await;
    assert_eq!(res.errors.len(), 1);
    assert_eq!(
        res.errors[0].message,
        "an active answer cannot contain NotSent"
    );
}

#[tokio::test]
async fn statuses_and_unqueried_kinds_are_mapped_without_filtering() {
    let schema = TestSchema::new().await;
    let (mut agent, token) = collecting(&schema);
    let now = agent.start + 20 * MINUTE;
    {
        let store = schema.store();
        insert_internal_network(&store, CUSTOMER);
        let seen = agent.start + MINUTE;
        agent.send(
            &store,
            vec![
                activity(seen, seen, "10.0.0.1"),
                activity(seen, seen, "10.0.1.1"),
            ],
        );
        agent.reach(
            &store,
            &[review_protocol::types::DaiObservationKind::IpActivity],
            agent.start + 10 * MINUTE,
        );
        apply_all(&store);
    }
    let collection_query = &queries(CUSTOMER)[4];
    let value = data_at(&schema, collection_query, now).await;
    assert_eq!(
        value["daiCollectionStatus"]["sites"][0]["activeQuery"]["state"],
        "CUSTOMER_OFF"
    );
    data(&schema, &settings(CUSTOMER, 0, true, "[]")).await;
    let value = data_at(&schema, collection_query, now).await;
    assert_eq!(
        value["daiCollectionStatus"]["sites"][0]["activeQuery"]["state"],
        "NO_QUERY_RANGES"
    );
    let value = data_at(&schema, &queries(CUSTOMER)[3], now).await;
    assert!(
        value["daiIpOnlyDevices"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .all(|edge| edge["node"]["activeQuery"]["status"] == "QUERIES_OFF")
    );
    data(
        &schema,
        &site(
            CUSTOMER,
            &format!("\"{token}\""),
            0,
            r#"["10.0.0.0/24"]"#,
            "[]",
            20,
        ),
    )
    .await;
    let value = data_at(&schema, &queries(CUSTOMER)[3], now).await;
    let rows = value["daiIpOnlyDevices"]["edges"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for edge in rows {
        let row = &edge["node"];
        let active = &row["activeQuery"];
        assert!(active["lastQuery"].is_null());
        assert_eq!(
            active["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kind| kind["kind"].clone())
                .collect::<Vec<_>>(),
            vec![json!("PTR"), json!("NBNS"), json!("MDNS"), json!("SSDP")]
        );
        assert!(
            active["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|kind| kind["answer"].is_null() && kind["lastResult"].is_null())
        );
    }
    let mut statuses = rows
        .iter()
        .map(|edge| edge["node"]["activeQuery"]["status"].as_str().unwrap())
        .collect::<Vec<_>>();
    statuses.sort_unstable();
    assert_eq!(statuses, vec!["NOT_QUERIED_YET", "NOT_QUERY_TARGET"]);
    let value = data_at(&schema, collection_query, now).await;
    let active = &value["daiCollectionStatus"]["sites"][0]["activeQuery"];
    assert_eq!(active["state"], "ON");
    assert_eq!(active["noDnsServers"], true);
}
