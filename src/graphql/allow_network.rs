use async_graphql::Result;
use review_database::{self as database, Store};

/// Returns the allow network list of a customer.
///
/// The group is always empty, because review-database no longer stores allow
/// or block networks.
///
/// # Errors
///
/// This function currently never fails.
pub fn get_allow_networks(_db: &Store, _customer_id: u32) -> Result<database::HostNetworkGroup> {
    Ok(database::HostNetworkGroup::default())
}

#[cfg(test)]
mod tests {
    use review_database::HostNetworkGroup;

    use super::get_allow_networks;
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn get_allow_networks_returns_an_empty_group() {
        let schema = TestSchema::new().await;
        let store = schema.store();

        assert_eq!(
            get_allow_networks(&store, 1).unwrap(),
            HostNetworkGroup::default()
        );
    }
}
