use super::Error;

// This internal method should be called after validating pagination paramerters by either
// `grapqhl::query` or `grapqhl::query_with_constraints`.
pub(crate) fn len(first: Option<usize>, last: Option<usize>) -> Result<usize, Error> {
    match (first, last) {
        (Some(len), _) | (_, Some(len)) => Ok(len),
        _ => Err(Error::MissingValidation),
    }
}

pub fn page_info<D: serde::de::DeserializeOwned>(
    is_first: bool,
    limit: usize,
    mut rows: Vec<D>,
) -> (Vec<D>, bool, bool) {
    let has_previous = has_previous(is_first, limit, rows.len());
    let has_next = has_next(is_first, limit, rows.len());
    if rows.len() > limit {
        if is_first {
            rows.pop();
        } else {
            rows.remove(0);
        }
    }
    (rows, has_previous, has_next)
}

/// Indicates whether more records exist prior to the slice defined by this
/// `Slicing`, assuming that at least `edge_count` records satisfy the
/// requirements of the `Slicing`.
///
/// This is based on `hasPreviousPage` defined in [GraphQL Cursor
/// Connections Specification][spec].
///
/// [spec]:
/// https://relay.dev/graphql/connections.htm#sec-undefined.PageInfo.Fields
fn has_previous(is_first: bool, len: usize, edge_count: usize) -> bool {
    if is_first {
        false
    } else {
        edge_count > len
    }
}

/// Indicates whether more records exist following the slice defined by this
/// `Slicing`, assuming that at least `edge_count` records satisfy the
/// requirements of the `Slicing`.
///
/// This is based on `hasNextPage` defined in [GraphQL Cursor Connections
/// Specification][spec].
///
/// [spec]:
/// https://relay.dev/graphql/connections.htm#sec-undefined.PageInfo.Fields
fn has_next(is_first: bool, len: usize, edge_count: usize) -> bool {
    if is_first {
        edge_count > len
    } else {
        false
    }
}
