//! Customer-scoping utilities for GraphQL authorization.
//!
//! This module provides helpers to centralize customer-scoping logic:
//! - Administrator semantics: when `customer_ids` is `None`, the user is treated
//!   as an admin with access to all resources.
//! - Membership checks for single customer IDs.
//! - Intersection computation for multi-customer collections.
//! - Iterator/collection filtering based on customer membership.
//! - Canonical unauthorized error for GraphQL handlers.

use async_graphql::ErrorExtensions;

/// Checks if a user is an administrator.
///
/// Returns `true` if `customer_ids` is `None`, indicating the user has access
/// to all customers. Returns `false` if the user has a specific list of
/// allowed customers (even if empty).
#[must_use]
pub fn is_admin(customer_ids: &Option<Vec<u32>>) -> bool {
    customer_ids.is_none()
}

/// Checks if a user is a member of a specific customer.
///
/// Returns `true` if:
/// - The user is an admin (`customer_ids` is `None`), or
/// - The user's `customer_ids` list contains the specified `customer_id`.
///
/// Returns `false` otherwise, including when `customer_ids` is an empty vector.
#[must_use]
pub fn is_member(customer_ids: &Option<Vec<u32>>, customer_id: u32) -> bool {
    match customer_ids {
        None => true, // Admin has access to all customers
        Some(ids) => ids.contains(&customer_id),
    }
}

/// Computes the intersection of customer IDs that a user is allowed to access.
///
/// Returns a vector of customer IDs from `items` that the user is allowed to see:
/// - If the user is an admin (`customer_ids` is `None`), returns all items.
/// - Otherwise, returns only items that are in the user's `customer_ids` list.
#[must_use]
pub fn membership_intersection(
    customer_ids: &Option<Vec<u32>>,
    items: impl IntoIterator<Item = u32>,
) -> Vec<u32> {
    match customer_ids {
        None => items.into_iter().collect(), // Admin sees all
        Some(allowed) => items
            .into_iter()
            .filter(|id| allowed.contains(id))
            .collect(),
    }
}

/// Filters an iterator of items by customer membership.
///
/// For each item, extracts the customer ID(s) using the provided closure `f`.
/// - If the user is an admin (`customer_ids` is `None`), all items pass through.
/// - Otherwise, only items where at least one of the item's customer IDs
///   intersects with the user's allowed customer IDs are included.
///
/// # Type Parameters
///
/// * `I` - The input iterator type
/// * `F` - A closure that extracts customer IDs from an item
/// * `T` - The item type
/// * `C` - An iterator of customer IDs extracted from an item
pub fn filter_by_membership<I, F, T, C>(customer_ids: &Option<Vec<u32>>, iter: I, f: F) -> Vec<T>
where
    I: IntoIterator<Item = T>,
    F: Fn(&T) -> C,
    C: IntoIterator<Item = u32>,
{
    match customer_ids {
        None => iter.into_iter().collect(), // Admin bypass - no filtering
        Some(allowed) => iter
            .into_iter()
            .filter(|item| f(item).into_iter().any(|id| allowed.contains(&id)))
            .collect(),
    }
}

/// Filters an iterator of items by a single customer ID.
///
/// This is a convenience helper for the common case where items have a single
/// customer ID rather than multiple.
///
/// - If the user is an admin (`customer_ids` is `None`), all items pass through.
/// - Otherwise, only items where the item's customer ID matches one of the
///   user's allowed customer IDs are included.
///
/// # Type Parameters
///
/// * `I` - The input iterator type
/// * `F` - A closure that extracts a single customer ID from an item
/// * `T` - The item type
pub fn filter_by_customer_id<I, F, T>(customer_ids: &Option<Vec<u32>>, iter: I, f: F) -> Vec<T>
where
    I: IntoIterator<Item = T>,
    F: Fn(&T) -> u32,
{
    filter_by_membership(customer_ids, iter, |item| std::iter::once(f(item)))
}

/// Creates a canonical unauthorized error for GraphQL handlers.
///
/// Returns an `async_graphql::Error` with an "unauthorized" message and an
/// "UNAUTHORIZED" error code extension.
#[must_use]
pub fn unauthorized_error() -> async_graphql::Error {
    async_graphql::Error::new("unauthorized").extend_with(|_, e| e.set("code", "UNAUTHORIZED"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data structures for filter tests
    struct Item {
        name: &'static str,
        customer_id: u32,
    }

    struct MultiCustomerItem {
        name: &'static str,
        customer_ids: Vec<u32>,
    }

    #[test]
    fn test_is_admin() {
        // None indicates admin
        assert!(is_admin(&None));

        // Some with empty vec is not admin
        assert!(!is_admin(&Some(vec![])));

        // Some with customer IDs is not admin
        assert!(!is_admin(&Some(vec![1, 2, 3])));
    }

    #[test]
    fn test_is_member_admin() {
        // Admin has access to any customer
        assert!(is_member(&None, 1));
        assert!(is_member(&None, 999));
    }

    #[test]
    fn test_is_member_with_allowed_customers() {
        let customer_ids = Some(vec![1, 2, 3]);

        // User is member of allowed customers
        assert!(is_member(&customer_ids, 1));
        assert!(is_member(&customer_ids, 2));
        assert!(is_member(&customer_ids, 3));

        // User is not member of other customers
        assert!(!is_member(&customer_ids, 4));
        assert!(!is_member(&customer_ids, 999));
    }

    #[test]
    fn test_is_member_empty_customer_list() {
        // User with empty customer list has no access
        let customer_ids = Some(vec![]);
        assert!(!is_member(&customer_ids, 1));
        assert!(!is_member(&customer_ids, 999));
    }

    #[test]
    fn test_membership_intersection_admin() {
        // Admin sees all items
        let items = vec![1, 2, 3, 4, 5];
        let result = membership_intersection(&None, items);
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_membership_intersection_with_allowed_customers() {
        let customer_ids = Some(vec![1, 3, 5]);
        let items = vec![1, 2, 3, 4, 5];

        let result = membership_intersection(&customer_ids, items);
        assert_eq!(result, vec![1, 3, 5]);
    }

    #[test]
    fn test_membership_intersection_no_overlap() {
        let customer_ids = Some(vec![10, 20, 30]);
        let items = vec![1, 2, 3, 4, 5];

        let result = membership_intersection(&customer_ids, items);
        assert!(result.is_empty());
    }

    #[test]
    fn test_membership_intersection_empty_user() {
        let customer_ids = Some(vec![]);
        let items = vec![1, 2, 3];

        let result = membership_intersection(&customer_ids, items);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_by_membership_admin() {
        let items = vec![
            MultiCustomerItem {
                name: "a",
                customer_ids: vec![1, 2],
            },
            MultiCustomerItem {
                name: "b",
                customer_ids: vec![3],
            },
            MultiCustomerItem {
                name: "c",
                customer_ids: vec![4, 5],
            },
        ];

        // Admin sees all
        let result = filter_by_membership(&None, items, |item| item.customer_ids.clone());
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_filter_by_membership_with_allowed_customers() {
        let items = vec![
            MultiCustomerItem {
                name: "a",
                customer_ids: vec![1, 2],
            },
            MultiCustomerItem {
                name: "b",
                customer_ids: vec![3],
            },
            MultiCustomerItem {
                name: "c",
                customer_ids: vec![4, 5],
            },
        ];

        // User with access to customers 1 and 4
        let customer_ids = Some(vec![1, 4]);
        let result = filter_by_membership(&customer_ids, items, |item| item.customer_ids.clone());

        // Should see items "a" (has customer 1) and "c" (has customer 4)
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "a");
        assert_eq!(result[1].name, "c");
    }

    #[test]
    fn test_filter_by_membership_no_overlap() {
        let items = vec![
            MultiCustomerItem {
                name: "a",
                customer_ids: vec![1, 2],
            },
            MultiCustomerItem {
                name: "b",
                customer_ids: vec![3],
            },
        ];

        let customer_ids = Some(vec![99]);
        let result = filter_by_membership(&customer_ids, items, |item| item.customer_ids.clone());

        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_by_customer_id_admin() {
        let items = vec![
            Item {
                name: "a",
                customer_id: 1,
            },
            Item {
                name: "b",
                customer_id: 2,
            },
            Item {
                name: "c",
                customer_id: 3,
            },
        ];

        // Admin sees all
        let result = filter_by_customer_id(&None, items, |item| item.customer_id);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_filter_by_customer_id_with_allowed_customers() {
        let items = vec![
            Item {
                name: "a",
                customer_id: 1,
            },
            Item {
                name: "b",
                customer_id: 2,
            },
            Item {
                name: "c",
                customer_id: 3,
            },
        ];

        // User with access to customers 1 and 3
        let customer_ids = Some(vec![1, 3]);
        let result = filter_by_customer_id(&customer_ids, items, |item| item.customer_id);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "a");
        assert_eq!(result[1].name, "c");
    }

    #[test]
    fn test_filter_by_customer_id_empty_user() {
        let items = vec![
            Item {
                name: "a",
                customer_id: 1,
            },
            Item {
                name: "b",
                customer_id: 2,
            },
        ];

        let customer_ids = Some(vec![]);
        let result = filter_by_customer_id(&customer_ids, items, |item| item.customer_id);

        assert!(result.is_empty());
    }

    #[test]
    fn test_unauthorized_error() {
        let error = unauthorized_error();
        assert_eq!(error.message, "unauthorized");

        // Check that the error has the code extension
        let extensions = error.extensions.unwrap();
        assert_eq!(
            extensions.get("code"),
            Some(&async_graphql::Value::String("UNAUTHORIZED".to_string()))
        );
    }
}
