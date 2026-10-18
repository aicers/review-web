use async_graphql::Result;
use review_database::{self as database, Store, event::Direction};

/// Returns the allow network list.
///
/// # Errors
///
/// Returns an error if the allow network database could not be retrieved.
pub fn get_allow_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    use review_database::Iterable;

    let map = db.allow_network_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    let key = customer_id.to_be_bytes();

    for res in map.prefix_iter(Direction::Forward, None, &key) {
        let allow_network = res?;
        hosts.extend(allow_network.networks.hosts());
        networks.extend(allow_network.networks.networks());
        ip_ranges.extend(allow_network.networks.ip_ranges().to_vec());
    }
    Ok(database::HostNetworkGroup::new(hosts, networks, ip_ranges))
}

#[cfg(test)]
mod tests {
    use review_database::{AllowNetwork, HostNetworkGroup};

    use super::get_allow_networks;
    use crate::graphql::TestSchema;

    fn allow_network(name: &str, customer_id: u32, networks: HostNetworkGroup) -> AllowNetwork {
        AllowNetwork {
            id: u32::MAX,
            name: name.to_string(),
            networks,
            description: String::new(),
            customer_id,
        }
    }

    #[tokio::test]
    async fn get_allow_networks_merges_the_customers_entries() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let map = store.allow_network_map();
        map.put(allow_network(
            "host",
            1,
            HostNetworkGroup::new(vec!["1.1.1.1".parse().unwrap()], vec![], vec![]),
        ))
        .unwrap();
        map.put(allow_network(
            "network",
            1,
            HostNetworkGroup::new(vec![], vec!["10.0.0.0/8".parse().unwrap()], vec![]),
        ))
        .unwrap();
        map.put(allow_network(
            "other",
            2,
            HostNetworkGroup::new(vec!["2.2.2.2".parse().unwrap()], vec![], vec![]),
        ))
        .unwrap();

        assert_eq!(
            get_allow_networks(&store, 1).unwrap(),
            HostNetworkGroup::new(
                vec!["1.1.1.1".parse().unwrap()],
                vec!["10.0.0.0/8".parse().unwrap()],
                vec![],
            )
        );
        assert_eq!(
            get_allow_networks(&store, 3).unwrap(),
            HostNetworkGroup::default()
        );
    }
}
