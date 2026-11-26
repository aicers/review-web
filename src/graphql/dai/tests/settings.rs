//! The device identification settings of a customer.

use serde_json::json;

use super::{CUSTOMER, OTHER, code, data, extension, refused, sensor, wall_clock};
use crate::graphql::TestSchema;

const FIELDS: &str = "customerId deviceAccountIdentification lastEnabledTime \
    inactivityMultiplier noLeaseInactivitySecs evidenceAgingSecs kerberosPreauthRealms \
    revision relayRevision";

fn update(revision: u64, enabled: bool, realms: &str) -> String {
    format!(
        r#"mutation {{ updateDaiCustomerSettings(customerId: "{CUSTOMER}", revision: "{revision}", input: {{
            deviceAccountIdentification: {enabled}, inactivityMultiplier: 3,
            noLeaseInactivitySecs: "7200", evidenceAgingSecs: "86400",
            kerberosPreauthRealms: {realms}
        }}) {{ {FIELDS} }} }}"#
    )
}

fn settings_query(customers: &[u32]) -> String {
    let ids = customers
        .iter()
        .map(|customer| format!("\"{customer}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ daiCustomerSettings(customerIds: [{ids}]) {{ {FIELDS} }} }}")
}

#[tokio::test]
async fn settings_never_written_read_as_the_defaults_in_order() {
    let schema = TestSchema::new().await;
    let defaults = |customer: u32| {
        json!({
            "customerId": customer.to_string(),
            "deviceAccountIdentification": false,
            "lastEnabledTime": null,
            "inactivityMultiplier": 2,
            "noLeaseInactivitySecs": "86400",
            "evidenceAgingSecs": "15552000",
            "kerberosPreauthRealms": [],
            "revision": "0",
            "relayRevision": "0",
        })
    };
    assert_eq!(
        data(&schema, &settings_query(&[OTHER, CUSTOMER])).await,
        json!({ "daiCustomerSettings": [defaults(OTHER), defaults(CUSTOMER)] })
    );
}

#[tokio::test]
async fn the_first_write_at_revision_0_stores_the_settings_and_a_default_site() {
    let schema = TestSchema::new().await;
    sensor(&schema.store(), "a.example.com", CUSTOMER);
    let before = wall_clock();
    let value = data(&schema, &update(0, true, r#"["CORP.EXAMPLE"]"#)).await;
    let after = wall_clock();

    let settings = &value["updateDaiCustomerSettings"];
    assert_eq!(settings["deviceAccountIdentification"], json!(true));
    assert_eq!(settings["inactivityMultiplier"], json!(3));
    assert_eq!(settings["noLeaseInactivitySecs"], json!("7200"));
    assert_eq!(settings["evidenceAgingSecs"], json!("86400"));
    assert_eq!(settings["kerberosPreauthRealms"], json!(["CORP.EXAMPLE"]));
    assert_eq!(settings["revision"], json!("1"));
    assert_eq!(settings["relayRevision"], json!("0"));
    let enabled_text = settings["lastEnabledTime"].clone();
    let enabled: jiff::Timestamp = settings["lastEnabledTime"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let enabled = i64::try_from(enabled.as_nanosecond()).unwrap();
    assert!((before..=after).contains(&enabled));

    // The default site is stored, with its token.
    let sites = schema.store().dai_sites(CUSTOMER).unwrap();
    assert_eq!(sites.len(), 1);
    assert!(sites[0].is_default);
    let sites = data(
        &schema,
        &format!(r#"{{ daiSites(customerId: "{CUSTOMER}") {{ token isDefault }} }}"#),
    )
    .await;
    assert_eq!(
        sites["daiSites"],
        json!([{ "token": schema.store().dai_sites(CUSTOMER).unwrap()[0].token, "isDefault": true }])
    );

    // Turning it off keeps the last-enabled time.
    let value = data(&schema, &update(1, false, "[]")).await;
    let settings = &value["updateDaiCustomerSettings"];
    assert_eq!(settings["deviceAccountIdentification"], json!(false));
    assert_eq!(settings["lastEnabledTime"], enabled_text);
    assert_eq!(
        schema
            .store()
            .dai_settings(CUSTOMER)
            .unwrap()
            .last_enabled_time,
        Some(enabled)
    );
    assert_eq!(settings["revision"], json!("2"));
}

#[tokio::test]
async fn a_stale_revision_is_refused_with_the_stored_one() {
    let schema = TestSchema::new().await;
    data(&schema, &update(0, true, "[]")).await;
    let stored = schema.store().dai_settings(CUSTOMER).unwrap();

    for revision in [0, 2] {
        let error = refused(&schema, &update(revision, false, "[]")).await;
        assert_eq!(code(&error).as_deref(), Some("STALE_REVISION"));
        assert_eq!(extension(&error, "storedRevision"), json!("1"));
    }
    assert_eq!(schema.store().dai_settings(CUSTOMER).unwrap(), stored);
}

#[tokio::test]
async fn a_value_out_of_range_is_refused_naming_it() {
    let schema = TestSchema::new().await;
    for (input, named) in [
        (
            r#"inactivityMultiplier: 0, noLeaseInactivitySecs: "1", evidenceAgingSecs: "1", kerberosPreauthRealms: []"#,
            "inactivity_multiplier",
        ),
        (
            r#"inactivityMultiplier: 1, noLeaseInactivitySecs: "0", evidenceAgingSecs: "1", kerberosPreauthRealms: []"#,
            "no_lease_inactivity_secs",
        ),
        (
            r#"inactivityMultiplier: 1, noLeaseInactivitySecs: "1", evidenceAgingSecs: "0", kerberosPreauthRealms: []"#,
            "evidence_aging_secs",
        ),
        (
            r#"inactivityMultiplier: 1, noLeaseInactivitySecs: "1", evidenceAgingSecs: "1", kerberosPreauthRealms: ["A", ""]"#,
            "kerberos_preauth_realms",
        ),
    ] {
        let mutation = format!(
            r#"mutation {{ updateDaiCustomerSettings(customerId: "{CUSTOMER}", revision: "0",
                input: {{ deviceAccountIdentification: true, {input} }}) {{ revision }} }}"#
        );
        let error = refused(&schema, &mutation).await;
        assert!(error.message.contains(named), "{}", error.message);
    }
    // A negative value does not parse.
    let mutation = format!(
        r#"mutation {{ updateDaiCustomerSettings(customerId: "{CUSTOMER}", revision: "0",
            input: {{ deviceAccountIdentification: true, inactivityMultiplier: -1,
            noLeaseInactivitySecs: "1", evidenceAgingSecs: "1", kerberosPreauthRealms: [] }}) {{ revision }} }}"#
    );
    refused(&schema, &mutation).await;

    let store = schema.store();
    assert_eq!(store.dai_settings(CUSTOMER).unwrap().revision, 0);
    assert_eq!(store.dai_sites(CUSTOMER).unwrap(), Vec::new());
}
