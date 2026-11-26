//! The device identification sites and the relay site table.

use serde_json::{Value, json};

use super::{CUSTOMER, OTHER, code, data, default_site, extension, refused, sensor};
use crate::graphql::TestSchema;

fn sites_query() -> String {
    format!(r#"{{ daiSites(customerId: "{CUSTOMER}") {{ token name isDefault sensors }} }}"#)
}

fn create(name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{ createDaiSite(customerId: "{CUSTOMER}", name: {name:?}, sensors: {sensors:?}) {{ token name isDefault sensors }} }}"#
    )
}

fn update(token: &str, name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{ updateDaiSite(customerId: "{CUSTOMER}", token: "{token}", name: {name:?}, sensors: {sensors:?}) {{ token name isDefault sensors }} }}"#
    )
}

fn remove(token: &str) -> String {
    format!(r#"mutation {{ removeDaiSite(customerId: "{CUSTOMER}", token: "{token}") }}"#)
}

fn relay(revision: u64, entries: &[(&str, &str, &str)]) -> String {
    let entries = entries
        .iter()
        .map(|(server, giaddr, site)| {
            format!(r#"{{ dhcpServer: "{server}", giaddr: "{giaddr}", site: "{site}" }}"#)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"mutation {{ replaceDaiRelaySites(customerId: "{CUSTOMER}", revision: "{revision}", entries: [{entries}]) }}"#
    )
}

/// Returns the site `name` of a `daiSites` answer.
fn listed<'a>(sites: &'a Value, name: &str) -> &'a Value {
    sites["daiSites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|site| site["name"] == name)
        .unwrap()
}

#[tokio::test]
async fn an_unsaved_default_site_is_shown_without_writing_it() {
    let schema = TestSchema::new().await;
    let (a, b) = {
        let store = schema.store();
        (
            sensor(&store, "a.example.com", CUSTOMER),
            sensor(&store, "b.example.com", CUSTOMER),
        )
    };
    sensor(&schema.store(), "c.example.com", OTHER);

    assert_eq!(
        data(&schema, &sites_query()).await,
        json!({ "daiSites": [{ "token": null, "name": "", "isDefault": true, "sensors": [a, b] }] })
    );
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), Vec::new());

    // After a site write the stored default site lists the sensors in no
    // other site.
    let created = data(&schema, &create("North", &[&b])).await;
    let token = created["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(token.len(), 8);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    );
    assert_eq!(
        created["createDaiSite"],
        json!({ "token": token, "name": "North", "isDefault": false, "sensors": [b] })
    );
    let default = default_site(&schema.store(), CUSTOMER);
    let sites = data(&schema, &sites_query()).await;
    assert_eq!(
        listed(&sites, ""),
        &json!({ "token": default, "name": "", "isDefault": true, "sensors": [a] })
    );
    assert_eq!(listed(&sites, "North")["sensors"], json!([b]));

    // A sensor returns to the default site by being removed from its site.
    let updated = data(&schema, &update(&token, "Northeast", &[])).await;
    assert_eq!(
        updated["updateDaiSite"],
        json!({ "token": token, "name": "Northeast", "isDefault": false, "sensors": [] })
    );
    let sites = data(&schema, &sites_query()).await;
    assert_eq!(listed(&sites, "")["sensors"], json!([a, b]));
}

#[tokio::test]
async fn a_display_name_must_be_valid_and_unique() {
    let schema = TestSchema::new().await;
    data(&schema, &create("North", &[])).await;
    let stored = schema.store().dai_sites(CUSTOMER).unwrap();

    for name in ["", "a|b", "a;b", "a,b", "a\"b"] {
        let error = refused(&schema, &create(name, &[])).await;
        assert!(error.message.contains("site name"), "{}", error.message);
    }
    let error = refused(&schema, &create("North", &[])).await;
    assert!(error.message.contains("North"), "{}", error.message);

    // The default site cannot be renamed.
    let default = default_site(&schema.store(), CUSTOMER);
    let error = refused(&schema, &update(&default, "Main", &[])).await;
    assert!(error.message.contains("default site"), "{}", error.message);

    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), stored);
}

#[tokio::test]
async fn a_sensor_is_in_one_site_of_its_customer() {
    let schema = TestSchema::new().await;
    let (a, b, c) = {
        let store = schema.store();
        (
            sensor(&store, "a.example.com", CUSTOMER),
            sensor(&store, "b.example.com", CUSTOMER),
            sensor(&store, "c.example.com", OTHER),
        )
    };
    let north = data(&schema, &create("North", &[&a])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let stored = schema.store().dai_sites(CUSTOMER).unwrap();

    // Another site holding the sensor is named.
    let error = refused(&schema, &create("South", &[&b, &a])).await;
    assert!(
        error.message.contains(&a)
            && error.message.contains("North")
            && error.message.contains(&north),
        "{}",
        error.message
    );
    // A name that is not a sensor of the customer.
    for name in [c.as_str(), "piglet.nowhere.example.com"] {
        let error = refused(&schema, &create("South", &[name])).await;
        assert!(error.message.contains(name), "{}", error.message);
    }
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), stored);
}

#[tokio::test]
async fn a_site_in_use_cannot_be_removed() {
    let schema = TestSchema::new().await;
    let a = sensor(&schema.store(), "a.example.com", CUSTOMER);
    let north = data(&schema, &create("North", &[&a])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let relayed = data(&schema, &create("Relayed", &[])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let empty = data(&schema, &create("Empty", &[])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    data(&schema, &relay(0, &[("10.0.0.254", "10.1.0.1", &relayed)])).await;
    let default = default_site(&schema.store(), CUSTOMER);
    let stored = schema.store().dai_sites(CUSTOMER).unwrap();

    for (token, cause) in [
        (&default, "default site"),
        (&north, "lists sensors"),
        (&relayed, "relay site table"),
        (&"nosuchst".to_string(), "no site"),
    ] {
        let error = refused(&schema, &remove(token)).await;
        assert!(error.message.contains(cause), "{}", error.message);
    }
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), stored);

    assert_eq!(
        data(&schema, &remove(&empty)).await,
        json!({ "removeDaiSite": empty })
    );
    assert!(
        schema
            .store()
            .dai_sites(CUSTOMER)
            .unwrap()
            .iter()
            .all(|site| site.token != empty)
    );
}

#[tokio::test]
async fn the_relay_site_table_is_replaced_whole_at_its_revision() {
    let schema = TestSchema::new().await;
    let north = data(&schema, &create("North", &[])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let relay_query = format!(
        r#"{{ daiRelaySites(customerId: "{CUSTOMER}") {{ revision entries {{ dhcpServer giaddr site }} }} }}"#
    );
    assert_eq!(
        data(&schema, &relay_query).await,
        json!({ "daiRelaySites": { "revision": "0", "entries": [] } })
    );

    assert_eq!(
        data(
            &schema,
            &relay(
                0,
                &[
                    ("10.0.0.254", "10.2.0.1", &north),
                    ("10.0.0.254", "10.1.0.1", &north)
                ]
            )
        )
        .await,
        json!({ "replaceDaiRelaySites": "1" })
    );
    let stored = json!({ "daiRelaySites": { "revision": "1", "entries": [
        { "dhcpServer": "10.0.0.254", "giaddr": "10.1.0.1", "site": north },
        { "dhcpServer": "10.0.0.254", "giaddr": "10.2.0.1", "site": north },
    ] } });
    assert_eq!(data(&schema, &relay_query).await, stored);

    // A stale revision.
    let error = refused(&schema, &relay(0, &[])).await;
    assert_eq!(code(&error).as_deref(), Some("STALE_REVISION"));
    assert_eq!(extension(&error, "storedRevision"), json!("1"));

    // Invalid entries.
    for (entries, cause) in [
        (
            vec![("10.0.0.254", "0.0.0.0", north.as_str())],
            "unspecified",
        ),
        (vec![("10.0.0.254", "::", north.as_str())], "unspecified"),
        (
            vec![
                ("10.0.0.254", "10.1.0.1", north.as_str()),
                ("10.0.0.254", "10.1.0.1", north.as_str()),
            ],
            "listed twice",
        ),
        (vec![("10.0.0.254", "10.1.0.1", "nosuchst")], "nosuchst"),
        (
            vec![("10.0.0.300", "10.1.0.1", north.as_str())],
            "dhcpServer",
        ),
    ] {
        let error = refused(&schema, &relay(1, &entries)).await;
        assert!(error.message.contains(cause), "{}", error.message);
    }
    assert_eq!(data(&schema, &relay_query).await, stored);
}
