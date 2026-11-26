//! The site condition on time series generation policies: a policy reads
//! the sensors of one site.

use serde_json::{Value, json};

use super::{CUSTOMER, MINUTE, after, code, data, default_site, extension, refused, sensor};
use crate::graphql::TestSchema;
use crate::graphql::time_series_generation_test_support::{
    PolicyShape, insert_internal_network, insert_policy, insert_shaped_policy,
};

fn sensor_list(sensors: &[&str]) -> String {
    format!("{sensors:?}")
}

fn insert(name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{
            insertTimeSeriesGenerationPolicy(
                customerId: "{CUSTOMER}", name: "{name}", rawEventKind: CONN, measure: COUNT,
                groupByUnit: IP, counterpartScope: ANY, slotSize: FIFTEEN_MINUTES,
                windowSize: ONE_DAY, utcOffset: 0, sensors: {}
            )
        }}"#,
        sensor_list(sensors)
    )
}

fn insert_from_type(name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{
            insertTimeSeriesGenerationPolicyFromType(
                customerId: "{CUSTOMER}", name: "{name}",
                timeSeriesType: {{ id: "server_daily_tls", version: "1" }},
                sensors: {}, utcOffset: 0
            )
        }}"#,
        sensor_list(sensors)
    )
}

fn policy_input(name: &str, sensors: &[&str]) -> String {
    format!(
        r#"{{
            name: "{name}", rawEventKind: CONN, measure: COUNT, groupByUnit: IP,
            counterpartScope: ANY, slotSize: FIFTEEN_MINUTES, windowSize: ONE_DAY,
            utcOffset: 0, sensors: {}
        }}"#,
        sensor_list(sensors)
    )
}

fn update(id: u32, name: &str, old: &[&str], new: &[&str]) -> String {
    format!(
        r#"mutation {{ updateTimeSeriesGenerationPolicy(id: "{id}", old: {}, new: {}) }}"#,
        policy_input(name, old),
        policy_input(name, new)
    )
}

fn create_site(name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{ createDaiSite(customerId: "{CUSTOMER}", name: "{name}", sensors: {}) {{ token }} }}"#,
        sensor_list(sensors)
    )
}

fn update_site(token: &str, name: &str, sensors: &[&str]) -> String {
    format!(
        r#"mutation {{ updateDaiSite(customerId: "{CUSTOMER}", token: "{token}", name: "{name}", sensors: {}) {{ token }} }}"#,
        sensor_list(sensors)
    )
}

/// Returns the stored policies of the store, as (name, sensors).
fn policies(schema: &TestSchema) -> Vec<(String, Vec<String>)> {
    use review_database::{Iterable, event::Direction};

    schema
        .store()
        .time_series_generation_policy_map()
        .iter(Direction::Forward, None)
        .map(|policy| {
            let policy = policy.unwrap();
            (policy.name, policy.sensors)
        })
        .collect()
}

/// Returns the `sites` extension listing `sites`, each a token and its
/// sensors, as it is expected: in token order, the sensors sorted.
fn expected_sites(mut sites: Vec<(String, Vec<String>)>) -> Value {
    sites.sort_unstable();
    Value::Array(
        sites
            .into_iter()
            .map(|(site, mut sensors)| {
                sensors.sort_unstable();
                json!({ "site": site, "sensors": sensors })
            })
            .collect(),
    )
}

#[tokio::test]
async fn a_policy_whose_sensors_span_two_sites_is_refused_with_the_sites() {
    let schema = TestSchema::new().await;
    let (a, b, c, draft) = {
        let store = schema.store();
        let a = sensor(&store, "a.example.com", CUSTOMER);
        let b = sensor(&store, "b.example.com", CUSTOMER);
        let c = sensor(&store, "c.example.com", CUSTOMER);
        insert_internal_network(&store, CUSTOMER);
        let draft = insert_policy(&store, "draft", CUSTOMER, &a);
        (a, b, c, draft)
    };
    let north = data(&schema, &create_site("North", &[&a])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let south = data(&schema, &create_site("South", &[&c, &b])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let stored = policies(&schema);
    let sites = expected_sites(vec![
        (north.clone(), vec![a.clone()]),
        (south.clone(), vec![c.clone(), b.clone()]),
    ]);

    // The policy lists the sensors of the second site out of order.
    let sensors = [c.as_str(), a.as_str(), b.as_str()];
    for mutation in [
        insert("custom", &sensors),
        insert_from_type("typed", &sensors),
        update(draft, "draft", &[&a], &sensors),
    ] {
        let error = refused(&schema, &mutation).await;
        assert_eq!(
            code(&error).as_deref(),
            Some("SENSORS_SPAN_SITES"),
            "{mutation}"
        );
        assert_eq!(extension(&error, "sites"), sites, "{mutation}");
        assert!(
            error.message.contains("more than one site"),
            "{}",
            error.message
        );
    }
    assert_eq!(policies(&schema), stored);

    // A policy over the sensors of one site is stored.
    data(&schema, &insert("south", &[&c, &b])).await;
    data(&schema, &update(draft, "draft", &[&a], &[&a])).await;
}

#[tokio::test]
async fn a_site_change_that_would_break_a_policy_is_refused_with_the_policies() {
    let schema = TestSchema::new().await;
    let (a, b, both, again) = {
        let store = schema.store();
        let a = sensor(&store, "a.example.com", CUSTOMER);
        let b = sensor(&store, "b.example.com", CUSTOMER);
        let both = stored_policy(&store, "both", &[&a, &b]);
        let again = stored_policy(&store, "again", &[&b, &a]);
        insert_policy(&store, "single", CUSTOMER, &a);
        (a, b, both, again)
    };
    let breaks = json!([
        { "id": both.to_string(), "name": "both" },
        { "id": again.to_string(), "name": "again" },
    ]);

    let error = refused(&schema, &create_site("North", &[&a])).await;
    assert_eq!(code(&error).as_deref(), Some("SITE_CHANGE_BREAKS_POLICY"));
    assert_eq!(extension(&error, "policies"), breaks);
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), Vec::new());

    let north = data(&schema, &create_site("North", &[])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let stored = schema.store().dai_sites(CUSTOMER).unwrap();
    let error = refused(&schema, &update_site(&north, "North", &[&b])).await;
    assert_eq!(code(&error).as_deref(), Some("SITE_CHANGE_BREAKS_POLICY"));
    assert_eq!(extension(&error, "policies"), breaks);
    assert_eq!(schema.store().dai_sites(CUSTOMER).unwrap(), stored);

    // Both sensors may move together.
    data(&schema, &update_site(&north, "North", &[&a, &b])).await;
}

/// Stores a draft policy `name` of [`CUSTOMER`] reading `sensors`, and
/// returns its id.
fn stored_policy(store: &review_database::Store, name: &str, sensors: &[&str]) -> u32 {
    insert_shaped_policy(store, name, CUSTOMER, sensors, PolicyShape::default())
}

/// Two sensors moved into one site at 12:02: a policy over both is refused
/// at 12:03, while the change is scheduled for 12:05, and accepted after
/// 12:05.
#[tokio::test]
async fn a_policy_follows_the_site_change_from_the_boundary_it_takes_effect() {
    let schema = TestSchema::new().await;
    let (a, b) = {
        let store = schema.store();
        (
            sensor(&store, "a.example.com", CUSTOMER),
            sensor(&store, "b.example.com", CUSTOMER),
        )
    };
    // Sensor a has been in North for a while; b is in the default site.
    let north = data(&schema, &create_site("North", &[&a])).await["createDaiSite"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let schema = after(schema, 10 * MINUTE).await;
    let default = default_site(&schema.store(), CUSTOMER);

    // 12:02: b moves into North, from the next boundary.
    data(&schema, &update_site(&north, "North", &[&a, &b])).await;

    // 12:03: the assignment in effect still has b in the default site.
    let error = refused(&schema, &insert("both", &[&a, &b])).await;
    assert_eq!(code(&error).as_deref(), Some("SENSORS_SPAN_SITES"));
    assert_eq!(
        extension(&error, "sites"),
        expected_sites(vec![
            (north.clone(), vec![a.clone()]),
            (default, vec![b.clone()])
        ])
    );
    assert_eq!(policies(&schema), Vec::new());

    // After 12:05 both are in North.
    let schema = after(schema, 5 * MINUTE).await;
    data(&schema, &insert("both", &[&a, &b])).await;
    assert_eq!(policies(&schema), [("both".to_string(), vec![a, b])]);
}
