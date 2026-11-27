//! Host-kind detection and customer-owned current policy group selection.

use std::collections::HashSet;

use async_graphql::{ID, Result, SimpleObject, resolver_utils::EnumType};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use review_database::Store;
use review_protocol::types::{EndpointScope, RawEventKind};
use uuid::Uuid;

use super::{
    filter,
    refusal::{RefusalCode, refusal},
};

const POLICY_TYPE: &str = "senta-policy";
const GROUP_PREFIX: &str = "group:";

/// Returns whether the stored Giganto kind is host telemetry.
pub(crate) fn is_host_kind(kind: &str) -> bool {
    // Endpoint log names in Giganto have a prefix absent from the protocol
    // enum. All other names share the GraphQL enum's snake-case spelling.
    let name = match kind {
        "endpoint_windows_event_log" => "windows_event_log",
        "endpoint_journald" => "journald",
        "endpoint_auditd" => "auditd",
        _ => kind,
    };
    filter::RawEventKind::items().iter().any(|item| {
        item.name.eq_ignore_ascii_case(name) && RawEventKind::from(item.value).is_host_kind()
    })
}

/// Returns a document scope, refusing malformed values at its top-level key.
pub(crate) fn parse_scope(value: &toml::Value) -> Result<EndpointScope> {
    if value.as_str() == Some("all") {
        return Ok(EndpointScope::All);
    }
    if let Some(table) = value.as_table().filter(|table| table.len() == 1)
        && let Some(groups) = table.get("groups").and_then(toml::Value::as_array)
    {
        let mut seen = HashSet::new();
        let ids: Option<Vec<_>> = groups
            .iter()
            .map(|group| {
                let id = group.as_str()?;
                (!id.is_empty() && seen.insert(id)).then(|| id.to_owned())
            })
            .collect();
        if let Some(ids) = ids.filter(|ids| !ids.is_empty()) {
            return Ok(EndpointScope::Groups(ids));
        }
    }
    Err(refusal(
        RefusalCode::InvalidDocument,
        "endpoint_scope must be all or a nonempty, duplicate-free groups table",
        "endpoint_scope",
        value_text(value),
    ))
}

/// Returns the offending value in the same form as definition refusals.
pub(crate) fn value_text(value: &toml::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

/// Checks policy-row ownership without reading the policy payload or endpoints.
pub(crate) fn check_groups(store: &Store, customer_id: u32, scope: &EndpointScope) -> Result<()> {
    let EndpointScope::Groups(groups) = scope else {
        return Ok(());
    };
    let documents = store.senta_endpoint_current_document_map();
    for (i, group) in groups.iter().enumerate() {
        let owned = Uuid::parse_str(group).is_ok()
            && documents.get(customer_id, POLICY_TYPE, &format!("{GROUP_PREFIX}{group}"))
                .map_err(|e| format!("cannot read current policy for customer {customer_id}, group {group:?}: {e:#}"))?
                .is_some();
        if !owned {
            return Err(refusal(
                RefusalCode::SourceNotAllowed,
                format!("{group:?} is not a policy-backed group of customer {customer_id}"),
                &format!("endpoint_scope.groups[{i}]"),
                group.as_str(),
            ));
        }
    }
    Ok(())
}

/// A policy-backed endpoint group selectable for a customer's host training.
#[derive(SimpleObject)]
pub(super) struct TrainingEndpointGroup {
    /// The UUID after `group:` in the current policy's target.
    group_id: ID,
    /// The current policy's extended or essential mode; null when unreadable or unknown.
    collection_mode: Option<String>,
}

/// Returns groups from current policy rows, retaining unreadable payloads.
pub(super) fn customer_groups(
    store: &Store,
    customer_id: u32,
) -> Result<Vec<TrainingEndpointGroup>> {
    let documents = store
        .senta_endpoint_current_document_map()
        .of_customer_typ(customer_id, POLICY_TYPE)
        .map_err(|e| {
            format!("cannot read current endpoint policies of customer {customer_id}: {e:#}")
        })?;
    Ok(documents
        .into_iter()
        .filter_map(|document| {
            let group = document.target.strip_prefix(GROUP_PREFIX)?;
            Uuid::parse_str(group).ok()?;
            Some(TrainingEndpointGroup {
                group_id: ID(group.to_owned()),
                collection_mode: collection_mode(&document.jws),
            })
        })
        .collect())
}

fn collection_mode(jws: &str) -> Option<String> {
    let mut segments = jws.split('.');
    segments.next()?;
    let payload = segments.next()?;
    segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match json.get("collection_mode")?.as_str()? {
        mode @ ("extended" | "essential") => Some(mode.to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_require_compact_base64url_json_and_known_top_level_string() {
        for mode in ["extended", "essential"] {
            let payload = serde_json::json!({ "collection_mode": mode }).to_string();
            assert_eq!(
                collection_mode(&format!(
                    "header.{}.signature",
                    URL_SAFE_NO_PAD.encode(payload)
                )),
                Some(mode.into())
            );
        }
        for jws in [
            "",
            "h",
            "h.p",
            "h.p.s.extra",
            "h.%.s",
            "h.e30=.s",
            "h._w.s",
            "h.bm90LWpzb24.s",
        ] {
            assert_eq!(collection_mode(jws), None, "{jws}");
        }
        for payload in [
            "{}",
            "null",
            "[]",
            r#"{"collection_mode":null}"#,
            r#"{"collection_mode":42}"#,
            r#"{"collection_mode":"unknown"}"#,
            r#"{"collection_mode":"EXTENDED"}"#,
            r#"{"nested":{"collection_mode":"extended"}}"#,
        ] {
            assert_eq!(
                collection_mode(&format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload))),
                None,
                "{payload}"
            );
        }
    }

    #[test]
    fn stored_host_names_use_the_shared_predicate() {
        for item in filter::RawEventKind::items() {
            let name = item.name.to_ascii_lowercase();
            let kind = RawEventKind::from(item.value);
            assert_eq!(is_host_kind(&name), kind.is_host_kind(), "{name}");
        }
        for name in [
            "endpoint_windows_event_log",
            "endpoint_journald",
            "endpoint_auditd",
        ] {
            assert!(is_host_kind(name));
        }
        for name in ["log", "syslog", "periodic_time_series", "unrecognized"] {
            assert!(!is_host_kind(name));
        }
    }
}
