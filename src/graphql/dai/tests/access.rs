//! Who may call each device identification query and mutation: the roles,
//! the customer scope and the deletion guard.

use review_database::Role;

use super::{CUSTOMER, OTHER, run_as, sensor};
use crate::graphql::TestSchema;
use crate::graphql::customer_deletion_guard::test_support::{
    assert_locked, assert_not_locked, put_running_job,
};

const DEVICE: &str = "6b7d2c4e-9a1f-4c3b-8e5d-0f1a2b3c4d5e";
const OTHER_DEVICE: &str = "1c2d3e4f-5a6b-4c7d-8e9f-a0b1c2d3e4f5";

/// Every DAI query, for `customer`.
fn queries(customer: u32) -> Vec<String> {
    vec![
        format!(r#"{{ daiCustomerSettings(customerIds: ["{customer}"]) {{ revision }} }}"#),
        format!(r#"{{ daiSites(customerId: "{customer}") {{ token name }} }}"#),
        format!(r#"{{ daiRelaySites(customerId: "{customer}") {{ revision }} }}"#),
        format!(
            r#"{{ daiResolve(customerId: "{customer}", items: [{{ ip: "10.0.0.1", at: "2026-11-26T00:00:00Z" }}]) {{ __typename }} }}"#
        ),
        format!(r#"{{ daiDevices(customerId: "{customer}") {{ totalCount }} }}"#),
        format!(r#"{{ daiIpOnlyDevices(customerId: "{customer}") {{ totalCount }} }}"#),
        format!(
            r#"{{ daiDevice(customerId: "{customer}", deviceId: "{DEVICE}") {{ deviceId }} }}"#
        ),
        format!(r#"{{ daiSearch(customerId: "{customer}", text: "printer") {{ truncated }} }}"#),
        format!(r#"{{ daiCollectionStatus(customerId: "{customer}") {{ candidateRanges }} }}"#),
        format!(r#"{{ daiRangeCandidates(customerId: "{customer}") {{ range }} }}"#),
        format!(r#"{{ daiIgnoredRanges(customerId: "{customer}") {{ range }} }}"#),
    ]
}

/// Every DAI mutation, for `customer`.
fn mutations(customer: u32) -> Vec<String> {
    vec![
        format!(
            r#"mutation {{ updateDaiCustomerSettings(customerId: "{customer}", revision: "0", input: {{
                deviceAccountIdentification: true, inactivityMultiplier: 2,
                noLeaseInactivitySecs: "3600", evidenceAgingSecs: "86400", kerberosPreauthRealms: []
            }}) {{ revision }} }}"#
        ),
        format!(
            r#"mutation {{ createDaiSite(customerId: "{customer}", name: "North", sensors: []) {{ token }} }}"#
        ),
        format!(
            r#"mutation {{ updateDaiSite(customerId: "{customer}", token: "nosuchst", name: "North", sensors: []) {{ token }} }}"#
        ),
        format!(r#"mutation {{ removeDaiSite(customerId: "{customer}", token: "nosuchst") }}"#),
        format!(
            r#"mutation {{ replaceDaiRelaySites(customerId: "{customer}", revision: "0", entries: []) }}"#
        ),
        format!(
            r#"mutation {{ importDaiDevices(customerId: "{customer}", rows: [{{ assetId: "A-1", macs: [], fixedIps: [] }}]) {{ outcome }} }}"#
        ),
        format!(
            r#"mutation {{ mergeDaiDevices(customerId: "{customer}", survivor: "{DEVICE}", others: ["{OTHER_DEVICE}"]) }}"#
        ),
        format!(
            r#"mutation {{ splitDaiDevice(customerId: "{customer}", deviceId: "{DEVICE}", identifiers: [{{ kind: MAC, value: "02:00:00:00:00:01" }}]) }}"#
        ),
        format!(
            r#"mutation {{ setDaiDeviceStates(customerId: "{customer}", deviceIds: ["{DEVICE}"], verdict: CONFIRMED) }}"#
        ),
        format!(
            r#"mutation {{ removeDaiService(customerId: "{customer}", deviceId: "{DEVICE}", port: 80, protocol: 6) }}"#
        ),
        format!(
            r#"mutation {{ ignoreDaiRangeCandidate(customerId: "{customer}", range: "10.1.0.0/16", account: "alice") }}"#
        ),
        format!(
            r#"mutation {{ unignoreDaiRangeCandidate(customerId: "{customer}", range: "10.1.0.0/16") }}"#
        ),
    ]
}

fn is_forbidden(res: &async_graphql::Response) -> bool {
    res.errors.iter().any(|error| error.message == "Forbidden")
}

#[tokio::test]
async fn every_query_answers_each_of_the_four_roles() {
    let schema = TestSchema::new().await;
    sensor(&schema.store(), "a.example.com", CUSTOMER);
    for role in [
        Role::SystemAdministrator,
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ] {
        for query in queries(CUSTOMER) {
            let res = run_as(&schema, &query, role, &[CUSTOMER]).await;
            assert!(res.errors.is_empty(), "{role:?} {query}: {:?}", res.errors);
        }
    }
}

#[tokio::test]
async fn every_mutation_refuses_the_manager_and_the_monitor() {
    let schema = TestSchema::new().await;
    for role in [Role::SecurityManager, Role::SecurityMonitor] {
        for mutation in mutations(CUSTOMER) {
            let res = run_as(&schema, &mutation, role, &[CUSTOMER]).await;
            assert!(is_forbidden(&res), "{role:?} {mutation}: {:?}", res.errors);
        }
    }
    let store = schema.store();
    assert_eq!(store.dai_settings(CUSTOMER).unwrap().revision, 0);
    assert_eq!(store.dai_sites(CUSTOMER).unwrap(), Vec::new());
    assert_eq!(store.dai_ignored_ranges(CUSTOMER).unwrap(), Vec::new());
}

#[tokio::test]
async fn every_mutation_works_for_both_administrator_roles() {
    for role in [Role::SystemAdministrator, Role::SecurityAdministrator] {
        let schema = TestSchema::new().await;
        for mutation in mutations(CUSTOMER) {
            let res = run_as(&schema, &mutation, role, &[CUSTOMER]).await;
            assert!(!is_forbidden(&res), "{role:?} {mutation}: {:?}", res.errors);
        }
        // The mutations that need no stored device or site took effect.
        let store = schema.store();
        assert_eq!(store.dai_settings(CUSTOMER).unwrap().revision, 1);
        assert!(
            store
                .dai_sites(CUSTOMER)
                .unwrap()
                .iter()
                .any(|site| site.name == "North")
        );
        assert_eq!(store.dai_relay_sites(CUSTOMER).unwrap().revision, 1);
    }
}

#[tokio::test]
async fn a_caller_scoped_to_other_customers_is_forbidden_everywhere() {
    let schema = TestSchema::new().await;
    for role in [
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ] {
        for query in queries(CUSTOMER) {
            let res = run_as(&schema, &query, role, &[OTHER]).await;
            assert!(is_forbidden(&res), "{role:?} {query}: {:?}", res.errors);
        }
    }
    for mutation in mutations(CUSTOMER) {
        let res = run_as(&schema, &mutation, Role::SecurityAdministrator, &[OTHER]).await;
        assert!(is_forbidden(&res), "{mutation}: {:?}", res.errors);
    }

    // One foreign id among the ids refuses the whole call.
    let query = format!(
        r#"{{ daiCustomerSettings(customerIds: ["{OTHER}", "{CUSTOMER}"]) {{ customerId }} }}"#
    );
    let res = run_as(&schema, &query, Role::SecurityMonitor, &[OTHER]).await;
    assert!(is_forbidden(&res), "{:?}", res.errors);
    assert!(res.data.into_json().unwrap().is_null());

    let store = schema.store();
    assert_eq!(store.dai_settings(CUSTOMER).unwrap().revision, 0);
    assert_eq!(store.dai_sites(CUSTOMER).unwrap(), Vec::new());
    assert_eq!(store.dai_ignored_ranges(CUSTOMER).unwrap(), Vec::new());
}

#[tokio::test]
async fn every_mutation_is_refused_while_the_customer_is_being_deleted() {
    let schema = TestSchema::new().await;
    put_running_job(&schema.store(), CUSTOMER, &[]);
    for mutation in mutations(CUSTOMER) {
        let res = schema.execute_as_system_admin(&mutation).await;
        assert_locked(&res);
    }
    // The reads still answer.
    for query in queries(CUSTOMER) {
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
    }
    {
        let store = schema.store();
        assert_eq!(store.dai_settings(CUSTOMER).unwrap().revision, 0);
        assert_eq!(store.dai_sites(CUSTOMER).unwrap(), Vec::new());
        assert_eq!(store.dai_relay_sites(CUSTOMER).unwrap().revision, 0);
        assert_eq!(store.dai_ignored_ranges(CUSTOMER).unwrap(), Vec::new());
    }

    // Another customer's writes are not held up.
    for mutation in mutations(OTHER) {
        let res = schema.execute_as_system_admin(&mutation).await;
        assert_not_locked(&res);
    }
}
