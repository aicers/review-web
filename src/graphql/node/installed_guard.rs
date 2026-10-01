//! Refusal of legacy node edits that would strand an installed instance.
//!
//! A row whose `instance` is `Some` was created by `REview`'s install path,
//! and only `removeService` removes it. `updateNodeDraft`, `applyNode`,
//! `applyNodeDraft` and `removeNodes` must not delete such a row, change its
//! kind, or move the node that holds it to another host, because doing so
//! leaves the package and its identity on the host with nothing recording that
//! a teardown is owed.

use async_graphql::{Error, Result};
use itertools::Itertools;
use review_database::{Node, NodeUpdate};

/// A row created by `REview`'s install path.
struct Numbered<'a> {
    key: &'a str,
    instance: u32,
}

/// What a refused change would have done to a node's numbered rows.
enum Refused<'a> {
    Update {
        deleted: Vec<&'a str>,
        rekinded: Vec<&'a str>,
        rehosted: bool,
    },
    Removal {
        missing: Vec<&'a str>,
    },
}

/// Refuses an update that would delete a numbered row, change its kind, or
/// change the active hostname of the node holding one.
///
/// `old` and `new` are the updates about to be passed to `NodeTable::update`,
/// after `merge_installation_state` has copied the stored install state into
/// both. Only `old` decides which rows are numbered. Whether `old` is stale is
/// left to `NodeTable::update`.
pub(super) fn check_update(id: u32, name: &str, old: &NodeUpdate, new: &NodeUpdate) -> Result<()> {
    let numbered = numbered_rows(
        old.agents.iter().map(|a| (a.key.as_str(), a.instance)),
        old.external_services
            .iter()
            .map(|s| (s.key.as_str(), s.instance)),
    );
    if numbered.is_empty() {
        return Ok(());
    }

    let mut deleted = Vec::new();
    let mut rekinded = Vec::new();
    for agent in old.agents.iter().filter(|a| a.instance.is_some()) {
        let mut kept = new.agents.iter().filter(|a| a.key == agent.key).peekable();
        if kept.peek().is_none() {
            deleted.push(agent.key.as_str());
        } else if kept.any(|a| a.kind != agent.kind) {
            rekinded.push(agent.key.as_str());
        }
    }
    for service in old
        .external_services
        .iter()
        .filter(|s| s.instance.is_some())
    {
        let mut kept = new
            .external_services
            .iter()
            .filter(|s| s.key == service.key)
            .peekable();
        if kept.peek().is_none() {
            deleted.push(service.key.as_str());
        } else if kept.any(|s| s.kind != service.kind) {
            rekinded.push(service.key.as_str());
        }
    }
    let old_hostname = old.profile.as_ref().map(|p| p.hostname.as_str());
    let new_hostname = new.profile.as_ref().map(|p| p.hostname.as_str());
    let rehosted = old_hostname != new_hostname;

    if deleted.is_empty() && rekinded.is_empty() && !rehosted {
        return Ok(());
    }
    Err(refusal(
        id,
        name,
        old_hostname.is_some(),
        &numbered,
        &Refused::Update {
            deleted,
            rekinded,
            rehosted,
        },
    ))
}

/// Refuses removing nodes that hold a numbered row, or that list a row key
/// whose row could not be found.
///
/// Each entry is a stored node with the keys `get_by_id` reported as missing
/// from the agent and external-service tables. Every offending node is named
/// in the one error returned.
pub(super) fn check_removal<'a>(
    nodes: impl IntoIterator<Item = (&'a Node, &'a [String], &'a [String])>,
) -> Result<()> {
    let messages: Vec<String> = nodes
        .into_iter()
        .filter_map(|(node, invalid_agents, invalid_external_services)| {
            let numbered = numbered_rows(
                node.agents.iter().map(|a| (a.key.as_str(), a.instance)),
                node.external_services
                    .iter()
                    .map(|s| (s.key.as_str(), s.instance)),
            );
            let missing: Vec<&str> = invalid_agents
                .iter()
                .chain(invalid_external_services)
                .map(String::as_str)
                .collect();
            if numbered.is_empty() && missing.is_empty() {
                return None;
            }
            Some(
                refusal(
                    node.id,
                    &node.name,
                    node.profile.is_some(),
                    &numbered,
                    &Refused::Removal { missing },
                )
                .message,
            )
        })
        .collect();
    if messages.is_empty() {
        Ok(())
    } else {
        Err(Error::new(messages.join("\n")))
    }
}

fn numbered_rows<'a>(
    agents: impl Iterator<Item = (&'a str, Option<u32>)>,
    external_services: impl Iterator<Item = (&'a str, Option<u32>)>,
) -> Vec<Numbered<'a>> {
    agents
        .chain(external_services)
        .filter_map(|(key, instance)| instance.map(|instance| Numbered { key, instance }))
        .collect()
}

fn refusal(
    id: u32,
    name: &str,
    has_hostname: bool,
    numbered: &[Numbered<'_>],
    refused: &Refused<'_>,
) -> Error {
    let node = format!("Node \"{name}\" (ID {id})");
    let numbered_keys = numbered.iter().map(|n| n.key).join(", ");

    let change = match refused {
        Refused::Update {
            deleted,
            rekinded,
            rehosted,
        } => {
            let mut parts = Vec::new();
            if !deleted.is_empty() {
                parts.push(format!(
                    "delete installed instance rows {}",
                    deleted.join(", ")
                ));
            }
            if !rekinded.is_empty() {
                parts.push(format!(
                    "change the kind of installed instance rows {}",
                    rekinded.join(", ")
                ));
            }
            if *rehosted {
                parts.push(format!(
                    "change the active hostname of the node, which holds installed instance rows \
                     {numbered_keys}"
                ));
            }
            format!(
                "this change is refused because it would {}",
                parts.join("; ")
            )
        }
        Refused::Removal { missing } if numbered.is_empty() => {
            return Error::new(format!(
                "{node} is not removed: it lists rows {} that could not be found, so REview \
                 cannot confirm they were not installed instances. An operator must investigate \
                 the node.",
                missing.join(", ")
            ));
        }
        Refused::Removal { missing } => {
            let unverified = if missing.is_empty() {
                String::new()
            } else {
                format!(
                    ", and it lists rows {} that could not be found, so REview cannot confirm \
                     they were not installed instances",
                    missing.join(", ")
                )
            };
            format!(
                "it cannot be removed because it holds installed instance rows \
                 {numbered_keys}{unverified}"
            )
        }
    };

    if has_hostname {
        Error::new(format!(
            "{node}: {change}. An installed instance must first be uninstalled with removeService."
        ))
    } else {
        let instances = numbered
            .iter()
            .map(|n| format!("{} (instance {})", n.key, n.instance))
            .join(", ");
        Error::new(format!(
            "{node} holds installed instances {instances} but has no active hostname, so the node \
             alone does not tell which host they were installed on; {change}. An operator must \
             investigate to establish that host before changing the node."
        ))
    }
}

#[cfg(test)]
mod tests {
    use review_database::{
        Agent, AgentKind, AgentStatus, ExternalService, ExternalServiceKind, ExternalServiceStatus,
        Lifecycle, NodeProfile,
    };

    use super::*;

    fn agent(key: &str, kind: AgentKind, instance: Option<u32>) -> Agent {
        Agent {
            node_id: 0,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance,
        }
    }

    fn service(key: &str, kind: ExternalServiceKind, instance: Option<u32>) -> ExternalService {
        ExternalService {
            node_id: 0,
            key: key.to_string(),
            kind,
            status: ExternalServiceStatus::Enabled,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance,
        }
    }

    fn profile(hostname: &str) -> NodeProfile {
        NodeProfile {
            customer_id: 0,
            description: String::new(),
            hostname: hostname.to_string(),
        }
    }

    fn update(
        profile: Option<NodeProfile>,
        agents: Vec<Agent>,
        external_services: Vec<ExternalService>,
    ) -> NodeUpdate {
        NodeUpdate {
            name: Some("n".to_string()),
            name_draft: Some("n".to_string()),
            profile: profile.clone(),
            profile_draft: profile,
            agents,
            external_services,
        }
    }

    fn numbered_node(profile: Option<NodeProfile>) -> NodeUpdate {
        update(
            profile,
            vec![
                agent("001.piglet", AgentKind::Sensor, Some(1)),
                agent("hog", AgentKind::SemiSupervised, None),
            ],
            vec![service(
                "002.giganto",
                ExternalServiceKind::DataStore,
                Some(2),
            )],
        )
    }

    #[test]
    fn unchanged_numbered_rows_pass() {
        let old = numbered_node(Some(profile("h")));
        let mut new = numbered_node(Some(profile("h")));
        new.name_draft = Some("renamed".to_string());
        new.agents.truncate(1);
        assert!(check_update(1, "n", &old, &new).is_ok());
    }

    #[test]
    fn unnumbered_node_passes_any_change() {
        let old = update(
            None,
            vec![agent("hog", AgentKind::SemiSupervised, None)],
            vec![service("giganto", ExternalServiceKind::DataStore, None)],
        );
        let new = update(Some(profile("h")), vec![], vec![]);
        assert!(check_update(1, "n", &old, &new).is_ok());
    }

    #[test]
    fn deleting_numbered_rows_is_refused() {
        let old = numbered_node(Some(profile("h")));
        let new = update(Some(profile("h")), vec![], vec![]);
        let err = check_update(1, "n", &old, &new).unwrap_err().message;
        assert!(err.contains("Node \"n\" (ID 1)"), "{err}");
        assert!(
            err.contains("delete installed instance rows 001.piglet, 002.giganto"),
            "{err}"
        );
        assert!(!err.contains("hog"), "{err}");
        assert!(err.contains("removeService"), "{err}");
    }

    #[test]
    fn rekinding_numbered_rows_is_refused() {
        let old = numbered_node(Some(profile("h")));
        let mut new = numbered_node(Some(profile("h")));
        new.agents[0].kind = AgentKind::Unsupervised;
        new.external_services[0].kind = ExternalServiceKind::TiContainer;
        let err = check_update(1, "n", &old, &new).unwrap_err().message;
        assert!(
            err.contains("change the kind of installed instance rows 001.piglet, 002.giganto"),
            "{err}"
        );
        assert!(err.contains("removeService"), "{err}");
    }

    #[test]
    fn duplicate_key_with_another_kind_is_refused() {
        let old = numbered_node(Some(profile("h")));
        let mut new = numbered_node(Some(profile("h")));
        new.agents
            .push(agent("001.piglet", AgentKind::Unsupervised, None));
        let err = check_update(1, "n", &old, &new).unwrap_err().message;
        assert!(err.contains("change the kind"), "{err}");
    }

    #[test]
    fn rehosting_numbered_node_is_refused() {
        for (old_profile, new_profile) in [
            (Some(profile("h")), Some(profile("h2"))),
            (Some(profile("h")), None),
        ] {
            let old = numbered_node(old_profile);
            let new = numbered_node(new_profile);
            let err = check_update(1, "n", &old, &new).unwrap_err().message;
            assert!(
                err.contains(
                    "change the active hostname of the node, which holds installed instance \
                     rows 001.piglet, 002.giganto"
                ),
                "{err}"
            );
            assert!(err.contains("removeService"), "{err}");
        }
    }

    #[test]
    fn same_hostname_with_other_profile_fields_passes() {
        let old = numbered_node(Some(profile("h")));
        let mut changed = profile("h");
        changed.customer_id = 7;
        changed.description = "moved".to_string();
        let new = numbered_node(Some(changed));
        assert!(check_update(1, "n", &old, &new).is_ok());
    }

    #[test]
    fn numbered_node_without_hostname_reports_inconsistent_state() {
        let old = numbered_node(None);
        for new in [
            numbered_node(Some(profile("h"))),
            update(None, vec![], vec![]),
        ] {
            let err = check_update(1, "n", &old, &new).unwrap_err().message;
            assert!(
                err.contains("001.piglet (instance 1), 002.giganto (instance 2)"),
                "{err}"
            );
            assert!(err.contains("has no active hostname"), "{err}");
            assert!(err.contains("operator must investigate"), "{err}");
            assert!(!err.contains("removeService"), "{err}");
        }
    }

    fn node(profile: Option<NodeProfile>, agents: Vec<Agent>) -> Node {
        Node {
            id: 3,
            name: "c".to_string(),
            name_draft: None,
            profile,
            profile_draft: None,
            agents,
            external_services: vec![],
            creation_time: chrono::Utc::now(),
        }
    }

    #[test]
    fn removal_messages() {
        let unnumbered = node(
            Some(profile("h")),
            vec![agent("hog", AgentKind::SemiSupervised, None)],
        );
        assert!(check_removal([(&unnumbered, &[][..], &[][..])]).is_ok());

        let missing = ["piglet".to_string()];
        let err = check_removal([(&unnumbered, &missing[..], &[][..])])
            .unwrap_err()
            .message;
        assert!(err.contains("Node \"c\" (ID 3) is not removed"), "{err}");
        assert!(err.contains("rows piglet that could not be found"), "{err}");
        assert!(!err.contains("removeService"), "{err}");
        assert!(!err.contains("holds installed"), "{err}");

        let numbered = node(
            Some(profile("h")),
            vec![agent("001.piglet", AgentKind::Sensor, Some(1))],
        );
        let gone = ["002.giganto".to_string()];
        let err = check_removal([(&numbered, &[][..], &gone[..])])
            .unwrap_err()
            .message;
        assert!(
            err.contains("holds installed instance rows 001.piglet"),
            "{err}"
        );
        assert!(
            err.contains("rows 002.giganto that could not be found"),
            "{err}"
        );
        assert!(err.contains("removeService"), "{err}");

        let hostless = node(None, vec![agent("001.piglet", AgentKind::Sensor, Some(1))]);
        let err = check_removal([(&hostless, &[][..], &[][..])])
            .unwrap_err()
            .message;
        assert!(err.contains("001.piglet (instance 1)"), "{err}");
        assert!(err.contains("has no active hostname"), "{err}");
        assert!(!err.contains("removeService"), "{err}");

        let err = check_removal([
            (&unnumbered, &[][..], &[][..]),
            (&numbered, &[][..], &[][..]),
            (&hostless, &[][..], &[][..]),
        ])
        .unwrap_err()
        .message;
        assert_eq!(err.lines().count(), 2, "{err}");
    }
}
