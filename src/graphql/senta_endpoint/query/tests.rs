use review_database::{
    Role, SentaEndpoint, SentaEndpointActiveList, SentaEndpointActiveListEntry,
    SentaEndpointCommand, SentaEndpointCommandState, SentaEndpointCurrentDocument,
    SentaEndpointCustomer, SentaEndpointDocumentResult, SentaEndpointDocumentResultKey,
    SentaEndpointEnrollmentAttempt, SentaEndpointEnrollmentResult, SentaEndpointEvent,
    SentaEndpointEventKey, SentaEndpointEventSource, SentaEndpointGigantoEntry,
    SentaEndpointGigantoLastReceived, SentaEndpointGigantoLastReceivedKey,
    SentaEndpointGigantoLoss, SentaEndpointGigantoLossKey, SentaEndpointGigantoNode,
    SentaEndpointKeysetDocument, SentaEndpointKeysetVersion, SentaEndpointStatusReport,
    SentaEndpointUnenrollRequest, Store,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::hex;
use crate::graphql::TestSchema;

const CUSTOMER_A: u32 = 1;
const CUSTOMER_B: u32 = 2;
/// A customer registered for Clumit Endpoint with no endpoint.
const CUSTOMER_C: u32 = 3;
const INSTALL_ID: &str = "install-1";
/// The base of every stored time, in nanoseconds since the Unix epoch.
const BASE: i64 = 1_700_000_000_000_000_000;

/// The endpoints of customer A, in endpoint id order.
const A1: u128 = 0x11;
const A2: u128 = 0x12;
const A3: u128 = 0x13;
const A4: u128 = 0x14;
/// The endpoint of customer B.
const B1: u128 = 0x21;
/// An endpoint id with no endpoint row.
const UNKNOWN: u128 = 0x99;

/// The fingerprint of the address roots of customer A.
const ROOT_A: [u8; 32] = [0xaa; 32];
/// The fingerprint of the address root of customer B.
const ROOT_B: [u8; 32] = [0xbb; 32];

const SCOPED_ROLES: [Role; 3] = [
    Role::SecurityAdministrator,
    Role::SecurityManager,
    Role::SecurityMonitor,
];

fn uuid(id: u128) -> Uuid {
    Uuid::from_u128(id)
}

fn id(id: u128) -> String {
    uuid(id).hyphenated().to_string()
}

/// The SPKI hash of the endpoint `id`.
fn spki(id: u128) -> [u8; 32] {
    [u8::try_from(id).unwrap(); 32]
}

/// The time `offset` nanoseconds after [`BASE`].
fn at(offset: i64) -> i64 {
    BASE + offset
}

/// The GraphQL text of [`at`]`(offset)`.
fn time(offset: i64) -> String {
    jiff::Timestamp::from_nanosecond(i128::from(at(offset)))
        .unwrap()
        .to_string()
}

fn node(host: &str, instance: u32) -> SentaEndpointGigantoNode {
    SentaEndpointGigantoNode {
        host: host.to_string(),
        instance,
    }
}

fn register_customer(store: &Store, customer_id: u32) {
    store
        .register_senta_endpoint_customer(
            &SentaEndpointCustomer {
                customer_id,
                trust_state: vec![1, 2, 3],
                customer_endpoint_id: uuid(0x1000 + u128::from(customer_id)),
                customer_key_name: format!("key-{customer_id}"),
                install_id: INSTALL_ID.to_string(),
                last_keyset: SentaEndpointKeysetVersion::default(),
                recovery_key_version: 1,
            },
            &SentaEndpointKeysetDocument {
                customer_id,
                recovery_epoch: 0,
                keyset_version: 0,
                signing_kid: "kid".to_string(),
                jws: "k.e.y".to_string(),
            },
        )
        .unwrap();
}

fn attempt(
    spki_hash: [u8; 32],
    attempt_id: u128,
    customer_id: u32,
    result: SentaEndpointEnrollmentResult,
) -> SentaEndpointEnrollmentAttempt {
    SentaEndpointEnrollmentAttempt {
        spki_hash,
        attempt_id: uuid(attempt_id),
        customer_id,
        request: vec![0, 1, 2, 255],
        source_address: "192.0.2.1".parse().unwrap(),
        received_at: at(1),
        result,
    }
}

fn pending(reason: &str) -> SentaEndpointEnrollmentResult {
    SentaEndpointEnrollmentResult::Pending {
        reason: reason.to_string(),
    }
}

fn enroll(store: &Store, endpoint_id: u128, customer_id: u32, standing: &str, connected: bool) {
    let attempt_id = 0x5000 + endpoint_id;
    store
        .senta_endpoint_enrollment_attempt_map()
        .insert(&attempt(
            spki(endpoint_id),
            attempt_id,
            customer_id,
            pending("awaiting_approval"),
        ))
        .unwrap();
    let offset = i64::try_from(endpoint_id).unwrap();
    store
        .approve_senta_endpoint_enrollment(
            &spki(endpoint_id),
            uuid(attempt_id),
            &format!("result-{endpoint_id:x}"),
            &SentaEndpoint {
                endpoint_id: uuid(endpoint_id),
                customer_id,
                customer_endpoint_id: uuid(0x1000 + u128::from(customer_id)),
                spki_hash: spki(endpoint_id),
                standing: standing.to_string(),
                host_name: format!("host-{endpoint_id:x}"),
                os: "linux".to_string(),
                senta_version: "1.0.0".to_string(),
                bundle: "default".to_string(),
                enrolled_at: at(10 + offset),
                last_connected_at: at(20 + offset),
                connected,
            },
        )
        .unwrap();
}

fn write_address_document(
    store: &Store,
    customer_id: u32,
    recovery_epoch: u64,
    version: u64,
    roots: &[[u8; 32]],
) {
    assert!(
        store
            .write_senta_endpoint_current_document(
                &SentaEndpointCurrentDocument {
                    customer_id,
                    typ: "address".to_string(),
                    target: "default".to_string(),
                    recovery_epoch,
                    version,
                    jws: "a.d.d".to_string(),
                    put_at: at(2),
                },
                roots,
            )
            .unwrap()
    );
}

fn report(store: &Store, endpoint_id: u128, slot: Option<(u64, u64)>) {
    store
        .senta_endpoint_status_report_map()
        .put(&SentaEndpointStatusReport {
            endpoint_id: uuid(endpoint_id),
            report: format!("report-{endpoint_id:x}"),
            received_at: at(30),
            address_document_slot: slot,
        })
        .unwrap();
}

fn giganto_entry(
    host: &str,
    instance: u32,
    applied_version: Option<u64>,
) -> SentaEndpointGigantoEntry {
    SentaEndpointGigantoEntry {
        node: node(host, instance),
        entry_id: uuid(0x7000 + u128::from(instance)),
        server_name: format!("{host}.example"),
        host: format!("{host}:38370"),
        applied_version,
        last_confirmed_at: applied_version.map(|_| at(40)),
        losses_fetched_through: None,
        events_fetched_through: None,
    }
}

/// Fills the store:
///
/// - customers A, B and C, C without an endpoint;
/// - A's endpoints `A1`..`A4` and B's `B1`, each with its approved attempt,
///   and a pending attempt of A and a denied one of B;
/// - address documents: A's at (1, 3) and (2, 5) both listing `ROOT_A`, and
///   B's at (2, 5) listing `ROOT_B`;
/// - status reports: `A1` at slot (2, 5), `A2` at the previous epoch's slot
///   (1, 3), `A3` without a slot, `A4` none, and `B1` at (2, 5);
/// - last-received rows of `A1` on two nodes;
/// - unenroll requests of `A1`, `B1` and `UNKNOWN`.
fn fill(store: &Store) {
    store
        .senta_endpoint_install_map()
        .register(INSTALL_ID, "{}", 1)
        .unwrap();
    for customer_id in [CUSTOMER_A, CUSTOMER_B, CUSTOMER_C] {
        register_customer(store, customer_id);
    }
    enroll(store, A1, CUSTOMER_A, "active", true);
    enroll(store, A2, CUSTOMER_A, "suspended", false);
    enroll(store, A3, CUSTOMER_A, "active", false);
    enroll(store, A4, CUSTOMER_A, "active", true);
    enroll(store, B1, CUSTOMER_B, "active", true);
    let attempts = store.senta_endpoint_enrollment_attempt_map();
    attempts
        .insert(&attempt(
            [0x01; 32],
            0x6001,
            CUSTOMER_A,
            pending("license_pending"),
        ))
        .unwrap();
    attempts
        .insert(&attempt(
            [0x02; 32],
            0x6002,
            CUSTOMER_B,
            SentaEndpointEnrollmentResult::Denied {
                reason: "denied".to_string(),
            },
        ))
        .unwrap();

    write_address_document(store, CUSTOMER_A, 1, 3, &[ROOT_A]);
    write_address_document(store, CUSTOMER_A, 2, 5, &[ROOT_A]);
    write_address_document(store, CUSTOMER_B, 2, 5, &[ROOT_B]);
    report(store, A1, Some((2, 5)));
    report(store, A2, Some((1, 3)));
    report(store, A3, None);
    report(store, B1, Some((2, 5)));

    let last_received = store.senta_endpoint_giganto_last_received_map();
    for (host, instance, offset) in [("giganto-b", 2, 52), ("giganto-a", 1, 51)] {
        last_received
            .put(&SentaEndpointGigantoLastReceived {
                key: SentaEndpointGigantoLastReceivedKey {
                    endpoint_id: uuid(A1),
                    node: node(host, instance),
                },
                last_received_at: at(offset),
                fetched_at: at(offset + 100),
            })
            .unwrap();
    }

    let unenroll = store.senta_endpoint_unenroll_request_map();
    for (endpoint_id, offset) in [(A1, 61), (B1, 62), (UNKNOWN, 63)] {
        unenroll
            .put(&SentaEndpointUnenrollRequest {
                endpoint_id: uuid(endpoint_id),
                received_at: at(offset),
            })
            .unwrap();
    }
}

async fn filled_schema() -> TestSchema {
    let schema = TestSchema::new().await;
    fill(&schema.store());
    schema
}

async fn as_admin(schema: &TestSchema, query: &str) -> Value {
    let response = schema.execute_as_system_admin(query).await;
    assert!(response.errors.is_empty(), "{query}: {:?}", response.errors);
    response.data.into_json().unwrap()
}

async fn as_scoped(schema: &TestSchema, query: &str, role: Role, customers: &[u32]) -> Value {
    let response = schema
        .execute_as_scoped_user(query, role, Some(customers.to_vec()))
        .await;
    assert!(
        response.errors.is_empty(),
        "{query} as {role:?}: {:?}",
        response.errors
    );
    response.data.into_json().unwrap()
}

fn messages(response: &async_graphql::Response) -> Vec<&str> {
    response
        .errors
        .iter()
        .map(|error| error.message.as_str())
        .collect()
}

async fn assert_forbidden(schema: &TestSchema, query: &str, role: Role, customers: &[u32]) {
    let response = schema
        .execute_as_scoped_user(query, role, Some(customers.to_vec()))
        .await;
    assert_eq!(messages(&response), ["Forbidden"], "{query} as {role:?}");
}

/// One query of each customer-bound field.
fn customer_bound_queries() -> Vec<String> {
    vec![
        "{ endpointEnrollmentAttempts { attemptId } }".to_string(),
        "{ endpoints { totalCount } }".to_string(),
        format!(
            r#"{{ endpointDocumentResults(endpointId: "{}") {{ typ }} }}"#,
            id(A1)
        ),
        format!(
            r#"{{ endpointCommands(endpointId: "{}") {{ commandId }} }}"#,
            id(A1)
        ),
        format!(
            r#"{{ endpointEvents(endpointId: "{}") {{ losses {{ reason }} }} }}"#,
            id(A1)
        ),
        format!(
            r#"{{ endpointTrustRootAdoption(fingerprint: "{}") {{ customerId }} }}"#,
            hex(&ROOT_A)
        ),
        "{ endpointUnenrollRequests { endpointId } }".to_string(),
    ]
}

const SYSTEM_ADMINISTRATOR_QUERIES: [&str; 2] = [
    "{ endpointActiveListStatus { version } }",
    "{ endpointTelemetryEntries { entryId } }",
];

#[tokio::test]
async fn customer_bound_queries_answer_all_four_roles() {
    let schema = filled_schema().await;
    for query in customer_bound_queries() {
        as_admin(&schema, &query).await;
        for role in SCOPED_ROLES {
            as_scoped(&schema, &query, role, &[CUSTOMER_A]).await;
        }
    }
}

#[tokio::test]
async fn cross_customer_queries_answer_only_a_system_administrator() {
    let schema = filled_schema().await;
    for query in SYSTEM_ADMINISTRATOR_QUERIES {
        as_admin(&schema, query).await;
        for role in SCOPED_ROLES {
            for customers in [&[][..], &[CUSTOMER_A], &[CUSTOMER_A, CUSTOMER_B]] {
                assert_forbidden(&schema, query, role, customers).await;
            }
        }
    }
}

#[tokio::test]
async fn a_caller_with_no_role_is_refused() {
    let schema = filled_schema().await;
    for query in customer_bound_queries()
        .iter()
        .map(String::as_str)
        .chain(SYSTEM_ADMINISTRATOR_QUERIES)
    {
        let response = schema.schema.execute(query).await;
        assert!(response.is_err(), "{query}");
    }
}

#[tokio::test]
async fn a_scoped_caller_sees_only_its_customers() {
    let schema = filled_schema().await;
    let attempts = "{ endpointEnrollmentAttempts { customerId } }";
    let endpoints = "{ endpoints { totalCount edges { node { endpointId } } } }";
    let unenroll = "{ endpointUnenrollRequests { endpointId customerId } }";
    let adoption = format!(
        r#"{{ endpointTrustRootAdoption(fingerprint: "{}") {{ customerId }} }}"#,
        hex(&ROOT_A)
    );
    for role in SCOPED_ROLES {
        let data = as_scoped(&schema, attempts, role, &[CUSTOMER_A]).await;
        let customers = data["endpointEnrollmentAttempts"].as_array().unwrap();
        assert_eq!(customers.len(), 5);
        assert!(customers.iter().all(|row| row["customerId"] == "1"));

        let data = as_scoped(&schema, endpoints, role, &[CUSTOMER_A]).await;
        assert_eq!(
            data["endpoints"],
            json!({
                "totalCount": "4",
                "edges": ([A1, A2, A3, A4]
                    .map(|endpoint| json!({"node": {"endpointId": id(endpoint)}}))),
            })
        );

        let data = as_scoped(&schema, unenroll, role, &[CUSTOMER_A]).await;
        assert_eq!(
            data,
            json!({"endpointUnenrollRequests": [{"endpointId": id(A1), "customerId": "1"}]})
        );

        let data = as_scoped(&schema, &adoption, role, &[CUSTOMER_A]).await;
        assert_eq!(
            data,
            json!({"endpointTrustRootAdoption": [{"customerId": "1"}]})
        );

        let data = as_scoped(&schema, endpoints, role, &[]).await;
        assert_eq!(data["endpoints"]["totalCount"], "0");
    }

    let data = as_admin(&schema, attempts).await;
    assert_eq!(
        data["endpointEnrollmentAttempts"].as_array().unwrap().len(),
        7
    );
    let data = as_admin(&schema, endpoints).await;
    assert_eq!(data["endpoints"]["totalCount"], "5");
    let data = as_admin(&schema, unenroll).await;
    assert_eq!(
        data,
        json!({"endpointUnenrollRequests": [
            {"endpointId": id(A1), "customerId": "1"},
            {"endpointId": id(B1), "customerId": "2"},
            {"endpointId": id(UNKNOWN), "customerId": null},
        ]})
    );
    let data = as_admin(&schema, &adoption).await;
    assert_eq!(
        data,
        json!({"endpointTrustRootAdoption": [
            {"customerId": "1"}, {"customerId": "2"}, {"customerId": "3"},
        ]})
    );
}

#[tokio::test]
async fn a_scoped_caller_is_refused_for_another_customer_or_an_unknown_endpoint() {
    let schema = filled_schema().await;
    let mut refused = Vec::new();
    for endpoint in [B1, UNKNOWN] {
        let endpoint = id(endpoint);
        refused.push(format!(
            r#"{{ endpointDocumentResults(endpointId: "{endpoint}") {{ typ }} }}"#
        ));
        refused.push(format!(
            r#"{{ endpointCommands(endpointId: "{endpoint}") {{ commandId }} }}"#
        ));
        refused.push(format!(
            r#"{{ endpointEvents(endpointId: "{endpoint}") {{ losses {{ reason }} }} }}"#
        ));
    }
    refused.push(r#"{ endpointEnrollmentAttempts(customerId: "2") { attemptId } }"#.to_string());
    refused.push(r#"{ endpoints(customerId: "2") { totalCount } }"#.to_string());
    for role in SCOPED_ROLES {
        for query in &refused {
            assert_forbidden(&schema, query, role, &[CUSTOMER_A]).await;
        }
    }

    // An unscoped caller gets whatever rows exist, here none.
    let data = as_admin(
        &schema,
        &format!(
            r#"{{ endpointDocumentResults(endpointId: "{0}") {{ typ }}
                endpointCommands(endpointId: "{0}") {{ commandId }}
                endpointEvents(endpointId: "{0}") {{ duplicateKeys {{ sequence }} losses {{ reason }} }} }}"#,
            id(UNKNOWN)
        ),
    )
    .await;
    assert_eq!(
        data,
        json!({
            "endpointDocumentResults": [],
            "endpointCommands": [],
            "endpointEvents": {"duplicateKeys": [], "losses": []},
        })
    );
    let data = as_admin(&schema, r#"{ endpoints(customerId: "2") { totalCount } }"#).await;
    assert_eq!(data["endpoints"]["totalCount"], "1");
}

#[tokio::test]
async fn enrollment_attempts_filter_by_state_and_customer() {
    let schema = filled_schema().await;
    let fields = "spkiHash attemptId customerId request sourceAddress receivedAt state reason enrollmentResult";

    let data = as_admin(
        &schema,
        &format!("{{ endpointEnrollmentAttempts(state: PENDING) {{ {fields} }} }}"),
    )
    .await;
    assert_eq!(
        data,
        json!({"endpointEnrollmentAttempts": [{
            "spkiHash": hex(&[0x01; 32]),
            "attemptId": id(0x6001),
            "customerId": "1",
            "request": "AAEC/w==",
            "sourceAddress": "192.0.2.1",
            "receivedAt": time(1),
            "state": "PENDING",
            "reason": "license_pending",
            "enrollmentResult": null,
        }]})
    );

    let data = as_admin(
        &schema,
        &format!("{{ endpointEnrollmentAttempts(state: DENIED) {{ {fields} }} }}"),
    )
    .await;
    assert_eq!(
        data["endpointEnrollmentAttempts"],
        json!([{
            "spkiHash": hex(&[0x02; 32]),
            "attemptId": id(0x6002),
            "customerId": "2",
            "request": "AAEC/w==",
            "sourceAddress": "192.0.2.1",
            "receivedAt": time(1),
            "state": "DENIED",
            "reason": "denied",
            "enrollmentResult": null,
        }])
    );

    let data = as_admin(
        &schema,
        r#"{ endpointEnrollmentAttempts(state: APPROVED, customerId: "1") { spkiHash attemptId state reason enrollmentResult } }"#,
    )
    .await;
    assert_eq!(
        data["endpointEnrollmentAttempts"],
        Value::Array(
            [A1, A2, A3, A4]
                .map(|endpoint| json!({
                    "spkiHash": hex(&spki(endpoint)),
                    "attemptId": id(0x5000 + endpoint),
                    "state": "APPROVED",
                    "reason": null,
                    "enrollmentResult": format!("result-{endpoint:x}"),
                }))
                .to_vec()
        )
    );

    let data = as_admin(
        &schema,
        r#"{ endpointEnrollmentAttempts(customerId: "2") { attemptId } }"#,
    )
    .await;
    assert_eq!(
        data["endpointEnrollmentAttempts"],
        json!([{"attemptId": id(0x6002)}, {"attemptId": id(0x5000 + B1)}])
    );

    for role in SCOPED_ROLES {
        let data = as_scoped(
            &schema,
            r#"{ endpointEnrollmentAttempts(state: PENDING, customerId: "1") { attemptId } }"#,
            role,
            &[CUSTOMER_A],
        )
        .await;
        assert_eq!(
            data["endpointEnrollmentAttempts"],
            json!([{"attemptId": id(0x6001)}])
        );
    }
}

#[tokio::test]
async fn endpoints_return_their_rows_reports_and_last_received_times() {
    let schema = filled_schema().await;
    let data = as_admin(
        &schema,
        r"{ endpoints(first: 2) { totalCount edges { node {
            endpointId customerId customerEndpointId spkiHash standing hostName os
            sentaVersion bundle enrolledAt lastConnectedAt connected
            statusReport { report receivedAt addressDocumentSlot { epoch version } }
            lastReceived { node { hostname instance } lastReceivedAt fetchedAt }
        } } } }",
    )
    .await;
    assert_eq!(
        data,
        json!({"endpoints": {"totalCount": "5", "edges": [
            {"node": {
                "endpointId": id(A1),
                "customerId": "1",
                "customerEndpointId": id(0x1001),
                "spkiHash": hex(&spki(A1)),
                "standing": "active",
                "hostName": "host-11",
                "os": "linux",
                "sentaVersion": "1.0.0",
                "bundle": "default",
                "enrolledAt": time(0x1b),
                "lastConnectedAt": time(0x25),
                "connected": true,
                "statusReport": {
                    "report": "report-11",
                    "receivedAt": time(30),
                    "addressDocumentSlot": {"epoch": "2", "version": "5"},
                },
                "lastReceived": [
                    {"node": {"hostname": "giganto-a", "instance": "1"},
                     "lastReceivedAt": time(51), "fetchedAt": time(151)},
                    {"node": {"hostname": "giganto-b", "instance": "2"},
                     "lastReceivedAt": time(52), "fetchedAt": time(152)},
                ],
            }},
            {"node": {
                "endpointId": id(A2),
                "customerId": "1",
                "customerEndpointId": id(0x1001),
                "spkiHash": hex(&spki(A2)),
                "standing": "suspended",
                "hostName": "host-12",
                "os": "linux",
                "sentaVersion": "1.0.0",
                "bundle": "default",
                "enrolledAt": time(0x1c),
                "lastConnectedAt": time(0x26),
                "connected": false,
                "statusReport": {
                    "report": "report-12",
                    "receivedAt": time(30),
                    "addressDocumentSlot": {"epoch": "1", "version": "3"},
                },
                "lastReceived": [],
            }},
        ]}})
    );

    let data = as_admin(
        &schema,
        r#"{ a3: endpoints(customerId: "1", standing: "active", connected: false) { edges { node { endpointId statusReport { addressDocumentSlot { epoch } } } } }
            a4: endpoints(connected: true, customerId: "1") { edges { node { endpointId statusReport { report } } } } }"#,
    )
    .await;
    assert_eq!(
        data,
        json!({
            "a3": {"edges": [{"node": {"endpointId": id(A3), "statusReport": {"addressDocumentSlot": null}}}]},
            "a4": {"edges": [
                {"node": {"endpointId": id(A1), "statusReport": {"report": "report-11"}}},
                {"node": {"endpointId": id(A4), "statusReport": null}},
            ]},
        })
    );
}

#[tokio::test]
async fn endpoints_filter_and_paginate_with_the_filtered_total_count() {
    let schema = filled_schema().await;
    let page = |arguments: &str| {
        format!(
            r"{{ endpoints({arguments}) {{ totalCount pageInfo {{ hasPreviousPage hasNextPage startCursor endCursor }} edges {{ node {{ endpointId }} }} }} }}"
        )
    };
    let ids = |data: &Value| -> Vec<String> {
        data["endpoints"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["endpointId"].as_str().unwrap().to_string())
            .collect()
    };

    let data = as_admin(&schema, &page(r#"standing: "active""#)).await;
    assert_eq!(data["endpoints"]["totalCount"], "4");
    assert_eq!(ids(&data), [A1, A3, A4, B1].map(id));

    let data = as_admin(&schema, &page("connected: true")).await;
    assert_eq!(data["endpoints"]["totalCount"], "3");
    assert_eq!(ids(&data), [A1, A4, B1].map(id));

    let data = as_admin(&schema, &page(r#"standing: "Active""#)).await;
    assert_eq!(data["endpoints"]["totalCount"], "0");

    let data = as_admin(&schema, &page(r#"standing: "active", first: 2"#)).await;
    assert_eq!(data["endpoints"]["totalCount"], "4");
    assert_eq!(ids(&data), [A1, A3].map(id));
    assert_eq!(data["endpoints"]["pageInfo"]["hasNextPage"], true);
    assert_eq!(data["endpoints"]["pageInfo"]["hasPreviousPage"], false);
    let cursor = data["endpoints"]["pageInfo"]["endCursor"]
        .as_str()
        .unwrap()
        .to_string();

    let data = as_admin(
        &schema,
        &page(&format!(
            r#"standing: "active", first: 2, after: "{cursor}""#
        )),
    )
    .await;
    assert_eq!(data["endpoints"]["totalCount"], "4");
    assert_eq!(ids(&data), [A4, B1].map(id));
    assert_eq!(data["endpoints"]["pageInfo"]["hasNextPage"], false);

    let data = as_admin(&schema, &page(r#"standing: "active", last: 3"#)).await;
    assert_eq!(ids(&data), [A3, A4, B1].map(id));
    assert_eq!(data["endpoints"]["pageInfo"]["hasPreviousPage"], true);
    assert_eq!(data["endpoints"]["pageInfo"]["hasNextPage"], false);
    let cursor = data["endpoints"]["pageInfo"]["startCursor"]
        .as_str()
        .unwrap()
        .to_string();

    let data = as_admin(
        &schema,
        &page(&format!(
            r#"standing: "active", last: 3, before: "{cursor}""#
        )),
    )
    .await;
    assert_eq!(ids(&data), [A1].map(id));
    assert_eq!(data["endpoints"]["pageInfo"]["hasPreviousPage"], false);

    let data = as_scoped(
        &schema,
        &page("connected: false, first: 1"),
        Role::SecurityMonitor,
        &[CUSTOMER_A],
    )
    .await;
    assert_eq!(data["endpoints"]["totalCount"], "2");
    assert_eq!(ids(&data), [A2].map(id));
    assert_eq!(data["endpoints"]["pageInfo"]["hasNextPage"], true);

    let response = schema.execute_as_system_admin(&page("first: 101")).await;
    assert!(response.is_err());
}

const ACTIVE_LIST_STATUS: &str = "{ endpointActiveListStatus {
    version
    entries { endpointId spkiHash customerEndpointId state }
    nodes { node { hostname instance } appliedVersion lastConfirmedAt lagging }
    appliedEverywhere
} }";

fn put_active_list(store: &Store, version: u64) {
    store
        .senta_endpoint_active_list_map()
        .put(&SentaEndpointActiveList {
            version,
            entries: vec![
                SentaEndpointActiveListEntry {
                    endpoint_id: uuid(A2),
                    spki_hash: spki(A2),
                    customer_endpoint_id: uuid(0x1001),
                    state: "suspended:operator".to_string(),
                },
                SentaEndpointActiveListEntry {
                    endpoint_id: uuid(A1),
                    spki_hash: spki(A1),
                    customer_endpoint_id: uuid(0x1001),
                    state: "active".to_string(),
                },
            ],
        })
        .unwrap();
}

fn put_giganto_entries(store: &Store, applied: &[Option<u64>]) {
    let table = store.senta_endpoint_giganto_entry_map();
    for (instance, applied_version) in (1..).zip(applied) {
        table
            .put(&giganto_entry("giganto", instance, *applied_version))
            .unwrap();
    }
}

fn node_status(instance: u32, applied: Option<u64>, lagging: bool) -> Value {
    json!({
        "node": {"hostname": "giganto", "instance": instance.to_string()},
        "appliedVersion": applied.map(|version| version.to_string()),
        "lastConfirmedAt": applied.map(|_| time(40)),
        "lagging": lagging,
    })
}

#[tokio::test]
async fn active_list_status_returns_the_stored_list_as_it_is() {
    let schema = TestSchema::new().await;
    put_active_list(&schema.store(), u64::MAX);
    put_giganto_entries(&schema.store(), &[Some(u64::MAX)]);
    let data = as_admin(&schema, ACTIVE_LIST_STATUS).await;
    assert_eq!(
        data,
        json!({"endpointActiveListStatus": {
            "version": u64::MAX.to_string(),
            "entries": [
                {"endpointId": id(A2), "spkiHash": hex(&spki(A2)),
                 "customerEndpointId": id(0x1001), "state": "suspended:operator"},
                {"endpointId": id(A1), "spkiHash": hex(&spki(A1)),
                 "customerEndpointId": id(0x1001), "state": "active"},
            ],
            "nodes": [node_status(1, Some(u64::MAX), false)],
            "appliedEverywhere": u64::MAX.to_string(),
        }})
    );
}

#[tokio::test]
async fn active_list_status_derives_lagging_and_applied_everywhere() {
    struct Case {
        name: &'static str,
        list: Option<u64>,
        nodes: &'static [Option<u64>],
        lagging: &'static [bool],
        applied_everywhere: Option<u64>,
    }
    let cases = [
        Case {
            name: "all nodes current",
            list: Some(7),
            nodes: &[Some(7), Some(7)],
            lagging: &[false, false],
            applied_everywhere: Some(7),
        },
        Case {
            name: "one node behind",
            list: Some(7),
            nodes: &[Some(7), Some(6)],
            lagging: &[false, true],
            applied_everywhere: Some(6),
        },
        Case {
            name: "one node without an applied version",
            list: Some(7),
            nodes: &[None, Some(7)],
            lagging: &[true, false],
            applied_everywhere: None,
        },
        Case {
            name: "no node",
            list: Some(7),
            nodes: &[],
            lagging: &[],
            applied_everywhere: Some(7),
        },
        Case {
            name: "no stored list",
            list: None,
            nodes: &[Some(7), None],
            lagging: &[false, false],
            applied_everywhere: None,
        },
        Case {
            name: "no stored list and no node",
            list: None,
            nodes: &[],
            lagging: &[],
            applied_everywhere: None,
        },
    ];
    for case in cases {
        let schema = TestSchema::new().await;
        if let Some(version) = case.list {
            put_active_list(&schema.store(), version);
        }
        put_giganto_entries(&schema.store(), case.nodes);
        let data = as_admin(&schema, ACTIVE_LIST_STATUS).await;
        let status = &data["endpointActiveListStatus"];
        assert_eq!(
            status["version"],
            json!(case.list.map(|version| version.to_string())),
            "{}",
            case.name
        );
        assert_eq!(
            status["entries"].as_array().unwrap().len(),
            if case.list.is_some() { 2 } else { 0 },
            "{}",
            case.name
        );
        let expected: Vec<_> = (1..)
            .zip(case.nodes.iter().zip(case.lagging))
            .map(|(instance, (applied, lagging))| node_status(instance, *applied, *lagging))
            .collect();
        assert_eq!(status["nodes"], json!(expected), "{}", case.name);
        assert_eq!(
            status["appliedEverywhere"],
            json!(case.applied_everywhere.map(|version| version.to_string())),
            "{}",
            case.name
        );
    }
}

#[tokio::test]
async fn telemetry_entries_list_every_giganto_entry() {
    let schema = TestSchema::new().await;
    {
        let store = schema.store();
        let table = store.senta_endpoint_giganto_entry_map();
        table.put(&giganto_entry("giganto-b", 2, None)).unwrap();
        table.put(&giganto_entry("giganto-a", 1, Some(3))).unwrap();
    }
    let data = as_admin(
        &schema,
        "{ endpointTelemetryEntries { node { hostname instance } entryId serverName host } }",
    )
    .await;
    assert_eq!(
        data,
        json!({"endpointTelemetryEntries": [
            {"node": {"hostname": "giganto-a", "instance": "1"}, "entryId": id(0x7001),
             "serverName": "giganto-a.example", "host": "giganto-a:38370"},
            {"node": {"hostname": "giganto-b", "instance": "2"}, "entryId": id(0x7002),
             "serverName": "giganto-b.example", "host": "giganto-b:38370"},
        ]})
    );
}

#[tokio::test]
async fn document_results_include_the_reply_that_names_no_document() {
    let schema = filled_schema().await;
    {
        let store = schema.store();
        let table = store.senta_endpoint_document_result_map();
        for (endpoint_id, typ, target, version, result) in [
            (A1, "keyset", "", Some(u64::MAX), "applied"),
            (A1, "", "", None, "malformed"),
            (A1, "address", "default", Some(5), "rejected:stale"),
            (A2, "address", "default", Some(5), "applied"),
        ] {
            table
                .put(&SentaEndpointDocumentResult {
                    key: SentaEndpointDocumentResultKey {
                        endpoint_id: uuid(endpoint_id),
                        typ: typ.to_string(),
                        target: target.to_string(),
                    },
                    version,
                    result: result.to_string(),
                    at: at(70),
                })
                .unwrap();
        }
    }
    let query = format!(
        r#"{{ endpointDocumentResults(endpointId: "{}") {{ typ target version result at }} }}"#,
        id(A1)
    );
    let expected = json!({"endpointDocumentResults": [
        {"typ": "", "target": "", "version": null, "result": "malformed", "at": time(70)},
        {"typ": "address", "target": "default", "version": "5", "result": "rejected:stale", "at": time(70)},
        {"typ": "keyset", "target": "", "version": u64::MAX.to_string(), "result": "applied", "at": time(70)},
    ]});
    assert_eq!(as_admin(&schema, &query).await, expected);
    for role in SCOPED_ROLES {
        assert_eq!(
            as_scoped(&schema, &query, role, &[CUSTOMER_A]).await,
            expected
        );
    }
}

#[tokio::test]
async fn commands_are_in_sequence_order() {
    let schema = filled_schema().await;
    {
        let store = schema.store();
        // Command id order is the reverse of sequence order.
        for (command_id, sequence) in [(0xc1, 3), (0xc2, 2), (0xc3, 1)] {
            store
                .insert_senta_endpoint_command(
                    CUSTOMER_A,
                    &SentaEndpointCommand {
                        command_id: uuid(command_id),
                        endpoint_id: uuid(A1),
                        sequence,
                        jws: format!("c.m.{sequence}"),
                        expires_at: at(80),
                        state: SentaEndpointCommandState::Pending,
                        result: None,
                    },
                )
                .unwrap();
        }
        let commands = store.senta_endpoint_command_map();
        commands
            .set_state(
                uuid(0xc1),
                SentaEndpointCommandState::Result,
                Some(&[0, 255]),
            )
            .unwrap();
        commands
            .set_state(uuid(0xc2), SentaEndpointCommandState::Sent, None)
            .unwrap();
    }
    let query = format!(
        r#"{{ endpointCommands(endpointId: "{}") {{ commandId sequence command expiresAt state result }} }}"#,
        id(A1)
    );
    let expected = json!({"endpointCommands": [
        {"commandId": id(0xc3), "sequence": "1", "command": "c.m.1", "expiresAt": time(80),
         "state": "PENDING", "result": null},
        {"commandId": id(0xc2), "sequence": "2", "command": "c.m.2", "expiresAt": time(80),
         "state": "SENT", "result": null},
        {"commandId": id(0xc1), "sequence": "3", "command": "c.m.3", "expiresAt": time(80),
         "state": "RESULT", "result": "AP8="},
    ]});
    assert_eq!(as_admin(&schema, &query).await, expected);
    for role in SCOPED_ROLES {
        assert_eq!(
            as_scoped(&schema, &query, role, &[CUSTOMER_A]).await,
            expected
        );
    }
}

fn fill_events(store: &Store) {
    let events = store.senta_endpoint_event_map();
    for (endpoint_id, offset, source, sequence, fetched_at) in [
        (A1, 100, SentaEndpointEventSource::Review, 1, None),
        (
            A1,
            200,
            SentaEndpointEventSource::Node(node("giganto-a", 1)),
            u64::MAX,
            Some(at(250)),
        ),
        (A1, 50, SentaEndpointEventSource::Review, 2, None),
        (A2, 100, SentaEndpointEventSource::Review, 3, None),
    ] {
        assert!(
            events
                .insert(&SentaEndpointEvent {
                    key: SentaEndpointEventKey {
                        endpoint_id: uuid(endpoint_id),
                        at: at(offset),
                        source,
                        sequence,
                    },
                    spki_hash: spki(endpoint_id),
                    addresses: vec!["192.0.2.7".to_string(), "198.51.100.7".to_string()],
                    replacement_count: 2,
                    fetched_at,
                })
                .unwrap()
        );
    }
    let losses = store.senta_endpoint_giganto_loss_map();
    for (endpoint_id, offset) in [(A1, 150), (A1, 40), (A2, 150)] {
        assert!(
            losses
                .insert(&SentaEndpointGigantoLoss {
                    key: SentaEndpointGigantoLossKey {
                        endpoint_id: uuid(endpoint_id),
                        received_at: at(offset),
                        node: node("giganto-b", 2),
                        stream_id: uuid(0x8000),
                        range_from: 10,
                        range_to: u64::MAX,
                        reason_code: "overflow".to_string(),
                    },
                    reason_detail: format!("detail-{offset}"),
                    fetched_at: at(offset + 1),
                })
                .unwrap()
        );
    }
}

#[tokio::test]
async fn events_return_both_sources_and_losses_since_a_time_inclusively() {
    let schema = filled_schema().await;
    fill_events(&schema.store());
    let fields = "duplicateKeys { at node { hostname instance } sequence spkiHash addresses replacementCount fetchedAt }
        losses { receivedAt node { hostname instance } streamId rangeFrom rangeTo reason detail fetchedAt }";
    let event = |offset: i64, node: Value, sequence: String, fetched_at: Value| {
        json!({
            "at": time(offset),
            "node": node,
            "sequence": sequence,
            "spkiHash": hex(&spki(A1)),
            "addresses": ["192.0.2.7", "198.51.100.7"],
            "replacementCount": "2",
            "fetchedAt": fetched_at,
        })
    };
    let loss = |offset: i64| {
        json!({
            "receivedAt": time(offset),
            "node": {"hostname": "giganto-b", "instance": "2"},
            "streamId": id(0x8000),
            "rangeFrom": "10",
            "rangeTo": u64::MAX.to_string(),
            "reason": "overflow",
            "detail": format!("detail-{offset}"),
            "fetchedAt": time(offset + 1),
        })
    };
    let review_at_50 = event(50, Value::Null, "2".to_string(), Value::Null);
    let review_at_100 = event(100, Value::Null, "1".to_string(), Value::Null);
    let node_at_200 = event(
        200,
        json!({"hostname": "giganto-a", "instance": "1"}),
        u64::MAX.to_string(),
        json!(time(250)),
    );

    let all = format!(
        r#"{{ endpointEvents(endpointId: "{}") {{ {fields} }} }}"#,
        id(A1)
    );
    assert_eq!(
        as_admin(&schema, &all).await,
        json!({"endpointEvents": {
            "duplicateKeys": [review_at_50, review_at_100.clone(), node_at_200.clone()],
            "losses": [loss(40), loss(150)],
        }})
    );

    let since = format!(
        r#"{{ endpointEvents(endpointId: "{}", since: "{}") {{ {fields} }} }}"#,
        id(A1),
        time(100)
    );
    let expected = json!({"endpointEvents": {
        "duplicateKeys": [review_at_100, node_at_200],
        "losses": [loss(150)],
    }});
    assert_eq!(as_admin(&schema, &since).await, expected);
    for role in SCOPED_ROLES {
        assert_eq!(
            as_scoped(&schema, &since, role, &[CUSTOMER_A]).await,
            expected
        );
    }

    let since_loss = format!(
        r#"{{ endpointEvents(endpointId: "{}", since: "{}") {{ duplicateKeys {{ sequence }} losses {{ detail }} }} }}"#,
        id(A1),
        time(150)
    );
    assert_eq!(
        as_admin(&schema, &since_loss).await,
        json!({"endpointEvents": {
            "duplicateKeys": [{"sequence": u64::MAX.to_string()}],
            "losses": [{"detail": "detail-150"}],
        }})
    );
}

#[tokio::test]
async fn trust_root_adoption_is_counted_per_customer() {
    let schema = filled_schema().await;
    let adoption = |fingerprint: [u8; 32]| {
        format!(
            r#"{{ endpointTrustRootAdoption(fingerprint: "{}") {{ customerId adopted total }} }}"#,
            hex(&fingerprint)
        )
    };
    let row = |customer_id: u32, adopted: usize, total: usize| {
        json!({
            "customerId": customer_id.to_string(),
            "adopted": adopted.to_string(),
            "total": total.to_string(),
        })
    };

    // A's `A1` at (2, 5) and `A2` at the previous epoch's (1, 3) adopted
    // `ROOT_A`; `A3` without a slot and `A4` without a report did not. B's
    // document at (2, 5) lists `ROOT_B`, not `ROOT_A`.
    assert_eq!(
        as_admin(&schema, &adoption(ROOT_A)).await,
        json!({"endpointTrustRootAdoption": [row(1, 2, 4), row(2, 0, 1), row(3, 0, 0)]})
    );
    assert_eq!(
        as_admin(&schema, &adoption(ROOT_B)).await,
        json!({"endpointTrustRootAdoption": [row(1, 0, 4), row(2, 1, 1), row(3, 0, 0)]})
    );
    assert_eq!(
        as_admin(&schema, &adoption([0xcc; 32])).await,
        json!({"endpointTrustRootAdoption": [row(1, 0, 4), row(2, 0, 1), row(3, 0, 0)]})
    );
    for role in SCOPED_ROLES {
        assert_eq!(
            as_scoped(&schema, &adoption(ROOT_B), role, &[CUSTOMER_B, CUSTOMER_C]).await,
            json!({"endpointTrustRootAdoption": [row(2, 1, 1), row(3, 0, 0)]})
        );
    }
}

#[tokio::test]
async fn malformed_arguments_are_refused() {
    let schema = filled_schema().await;
    let mut queries = Vec::new();
    for customer_id in ["-1", "4294967296", "a"] {
        queries.push(format!(
            r#"{{ endpointEnrollmentAttempts(customerId: "{customer_id}") {{ attemptId }} }}"#
        ));
        queries.push(format!(
            r#"{{ endpoints(customerId: "{customer_id}") {{ totalCount }} }}"#
        ));
    }
    for endpoint_id in ["not-a-uuid", "", "0000000000000000000000000000001"] {
        queries.push(format!(
            r#"{{ endpointDocumentResults(endpointId: "{endpoint_id}") {{ typ }} }}"#
        ));
        queries.push(format!(
            r#"{{ endpointCommands(endpointId: "{endpoint_id}") {{ commandId }} }}"#
        ));
        queries.push(format!(
            r#"{{ endpointEvents(endpointId: "{endpoint_id}") {{ losses {{ reason }} }} }}"#
        ));
    }
    let short = "a".repeat(63);
    let long = "a".repeat(65);
    let upper = "A".repeat(64);
    let not_hex = "g".repeat(64);
    for fingerprint in [short.as_str(), &long, &upper, &not_hex, ""] {
        queries.push(format!(
            r#"{{ endpointTrustRootAdoption(fingerprint: "{fingerprint}") {{ customerId }} }}"#
        ));
    }
    for query in &queries {
        let response = schema.execute_as_system_admin(query).await;
        assert_eq!(response.errors.len(), 1, "{query}");
        assert_ne!(messages(&response), ["Forbidden"], "{query}");
        let response = schema
            .execute_as_scoped_user(query, Role::SecurityMonitor, Some(vec![CUSTOMER_A]))
            .await;
        assert_eq!(response.errors.len(), 1, "{query}");
    }
}
