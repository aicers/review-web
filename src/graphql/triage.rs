pub(super) mod response;

use async_graphql::{Enum, InputObject};
use review_database as database;
use serde::Deserialize;

use super::{
    Role, RoleGuard,
    filter::{DetectionModel, RawEventKind},
};

#[derive(Default)]
pub(super) struct TriageResponseQuery;

#[derive(Default)]
pub(super) struct TriageResponseMutation;

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize)]
#[graphql(remote = "database::ValueKind")]
pub enum ValueKind {
    String,
    Integer,
    UInteger,
    Vector,
    Float,
    IpAddr,
    Bool,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize)]
#[graphql(remote = "database::AttrCmpKind")]
pub enum AttrCmpKind {
    Less,
    Equal,
    Greater,
    LessOrEqual,
    GreaterOrEqual,
    Contain,
    OpenRange,
    CloseRange,
    LeftOpenRange,
    RightOpenRange,
    NotEqual,
    NotContain,
    NotOpenRange,
    NotCloseRange,
    NotLeftOpenRange,
    NotRightOpenRange,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize)]
#[graphql(remote = "database::ResponseKind")]
pub enum ResponseKind {
    Manual,
    Watchlist,
    ExclusionList,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize)]
#[graphql(remote = "database::EventCategory")]
#[repr(u8)]
pub enum ThreatCategory {
    Reconnaissance = 1,  // 1st (the first in the kill chain)
    InitialAccess,       // 3rd
    Execution,           // 4th
    CredentialAccess,    // 8th
    Discovery,           // 9th
    LateralMovement,     // 10th
    CommandAndControl,   // 12th
    Exfiltration,        // 13th
    Impact,              // 14th (the last in the kill chain)
    Collection,          // 11th
    DefenseEvasion,      // 7th
    Persistence,         // 5th
    PrivilegeEscalation, // 6th
    ResourceDevelopment, // 2nd
}

#[derive(Clone, InputObject)]
pub(super) struct PacketAttrInput {
    raw_event_kind: RawEventKind,
    attr_name: String,
    value_kind: ValueKind,
    cmp_kind: AttrCmpKind,
    first_value: Vec<u8>,
    second_value: Option<Vec<u8>>,
    weight: Option<f64>,
}

/// A condition of an inline triage policy on a detection event's own score.
///
/// The condition adds its `weight` to the policy's score of an event when the
/// event's category is `threatCategory`, its detection model is
/// `detectionModel`, and its score is at least `score`. A null
/// `threatCategory` matches only an event with no category. An omitted
/// `weight` counts as 1.0.
#[derive(Clone, InputObject)]
pub(super) struct ScoreConditionInput {
    threat_category: Option<ThreatCategory>,
    detection_model: DetectionModel,
    score: f64,
    weight: Option<f64>,
}

impl From<&ScoreConditionInput> for database::ScoreCondition {
    fn from(c: &ScoreConditionInput) -> Self {
        Self {
            threat_category: c.threat_category.map(Into::into),
            detection_model: c.detection_model.into(),
            score: c.score,
            weight: c.weight,
        }
    }
}

#[derive(Clone, InputObject)]
pub(super) struct ResponseInput {
    minimum_score: f64,
    kind: ResponseKind,
}

impl From<&ResponseInput> for database::Response {
    fn from(r: &ResponseInput) -> Self {
        Self {
            minimum_score: r.minimum_score,
            kind: r.kind.into(),
        }
    }
}

impl From<&PacketAttrInput> for database::PacketAttr {
    fn from(p: &PacketAttrInput) -> Self {
        Self {
            raw_event_kind: p.raw_event_kind.into(),
            attr_name: p.attr_name.clone(),
            value_kind: p.value_kind.into(),
            cmp_kind: p.cmp_kind.into(),
            first_value: p.first_value.clone(),
            second_value: p.second_value.clone(),
            weight: p.weight,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use review_protocol::types::{
        Detail, DetectionEvent, EventCategory, PrimarySubject, RawEventBody, RawEventKind,
        ThreatRole, raw_event,
    };

    use crate::graphql::{
        TestSchema,
        event_test_support::{
            INLINE_POLICY_SENSOR, PutEvent, conn_body, dns_event, inline_policy_schema, raw_event,
            subject_event,
        },
    };

    /// A DCE/RPC packet attribute shared by the inline-policy tests, so that
    /// only the score condition differs between them.
    const DCE_RPC_PACKET_ATTR: &str = r#"[{
        rawEventKind: DCE_RPC
        attrName: "Presentation Context ID"
        valueKind: U_INTEGER
        cmpKind: EQUAL
        firstValue: [1]
        weight: 1.0
    }]"#;

    /// Runs `detectionEventsByArrival` with a single inline policy built from the
    /// given `packetAttr` and `score` lists.
    async fn arrival_with_inline_policy(
        schema: &TestSchema,
        packet_attr: &str,
        score: &str,
    ) -> async_graphql::Response {
        let query = format!(
            r#"{{
                detectionEventsByArrival(
                    customerId: "1"
                    policies: [{{
                        id: 0
                        packetAttr: {packet_attr}
                        score: {score}
                        response: []
                    }}]
                    first: 1
                ) {{
                    events {{ id }}
                }}
            }}"#
        );
        schema.execute_as_system_admin(&query).await
    }

    #[tokio::test]
    async fn dce_rpc_raw_event_kind_accepted_in_inline_policy() {
        let schema = TestSchema::new().await;

        // Exercises the remote enum conversions used by PacketAttrInput.
        let res = arrival_with_inline_policy(&schema, DCE_RPC_PACKET_ATTR, "[]").await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn inline_policy_accepts_null_threat_category() {
        let schema = TestSchema::new().await;

        let res = arrival_with_inline_policy(
            &schema,
            DCE_RPC_PACKET_ATTR,
            "[{ threatCategory: null, detectionModel: PORT_SCAN, score: 0.25 }]",
        )
        .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn inline_policy_rejects_missing_detection_model() {
        let schema = TestSchema::new().await;

        // detectionModel is required even when threatCategory is null.
        let res = arrival_with_inline_policy(
            &schema,
            DCE_RPC_PACKET_ATTR,
            "[{ threatCategory: null, score: 0.25 }]",
        )
        .await;
        assert!(
            !res.errors.is_empty(),
            "expected validation error, got {res:?}"
        );
    }

    #[tokio::test]
    async fn removed_triage_policy_and_exclusion_surface_is_rejected() {
        let schema = TestSchema::new().await;

        // Names that embed the review-database exclusion-reason type name are
        // split with `concat!`, so a search for that type finds no remaining
        // reference once the table is dropped.
        let operations = [
            r"{ triagePolicyList { totalCount } }",
            r#"{ triagePolicy(id: "0") { name } }"#,
            r#"mutation {
                insertTriagePolicy(
                    name: "p", triageExclusionId: [], packetAttr: [], score: [], response: []
                )
            }"#,
            r#"mutation {
                updateTriagePolicy(
                    id: "0"
                    old: {
                        name: "p", triageExclusionId: [], packetAttr: [], score: [], response: []
                    }
                    new: {
                        name: "q", triageExclusionId: [], packetAttr: [], score: [], response: []
                    }
                )
            }"#,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            r"{ triageExclusionReasons { name } }",
            r#"{ triageExclusionReason(id: "0") { name } }"#,
            concat!(
                "mutation { insertTriage",
                r#"ExclusionReason(input: { name: "r", description: "", domain: ["a.com"] }) }"#
            ),
            concat!(
                "mutation { updateTriage",
                r#"ExclusionReason(
                    id: "0"
                    old: { name: "r", description: "", domain: ["a.com"] }
                    new: { name: "s", description: "", domain: ["a.com"] }
                ) }"#
            ),
            concat!(
                "mutation { removeTriage",
                r#"ExclusionReasons(ids: ["0"]) }"#
            ),
            r"{ eventTriageList(filter: {}) { __typename } }",
        ];
        for operation in operations {
            let res = schema.execute_as_system_admin(operation).await;
            assert!(
                !res.errors.is_empty(),
                "expected an error for {operation}, got {res:?}"
            );
            assert!(
                res.errors
                    .iter()
                    .any(|e| e.message.starts_with("Unknown field")),
                "expected an unknown-field error for {operation}, got {:?}",
                res.errors
            );
        }

        let types = [
            "TriagePolicy",
            "TriagePolicyConnection",
            "TriagePolicyEdge",
            "TriagePolicyInput",
            "PacketAttr",
            "Confidence",
            "Response",
            concat!("Triage", "ExclusionReason"),
            concat!("Triage", "ExclusionReasonInput"),
            "ExclusionReason",
            "IpAddressTriageExclusion",
            "DomainTriageExclusion",
            "HostnameTriageExclusion",
            "UriTriageExclusion",
            "EventTriageExclusionInput",
        ];
        for name in types {
            let res = schema
                .execute_as_system_admin(&format!(r#"{{ __type(name: "{name}") {{ name }} }}"#))
                .await;
            assert!(res.errors.is_empty(), "errors for {name}: {:?}", res.errors);
            assert_eq!(
                res.data.to_string(),
                "{__type: null}",
                "type {name} is still in the schema"
            );
        }
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("a test address")
    }

    fn at(second: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(1_700_000_000 + second).expect("a test time")
    }

    /// Stores `events` and returns, in arrival order, the `triageScores` the
    /// inline policy with `packet_attr`, `score` and a minimum score of
    /// `minimum` gives each of them, as JSON.
    async fn scores_of(
        events: &[DetectionEvent],
        packet_attr: &str,
        score: &str,
        minimum: f64,
    ) -> Vec<serde_json::Value> {
        let schema = inline_policy_schema().await;
        {
            let guard = schema.store();
            for event in events {
                guard.events().put_event(event).unwrap();
            }
        }
        let query = format!(
            r#"{{
                detectionEventsByArrival(
                    customerId: "1"
                    policies: [{{
                        id: 3
                        packetAttr: {packet_attr}
                        score: {score}
                        response: [{{ minimumScore: {minimum:?}, kind: MANUAL }}]
                    }}]
                ) {{
                    events {{ triageScores {{ policyId score }} }}
                }}
            }}"#
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        data["detectionEventsByArrival"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["triageScores"].clone())
            .collect()
    }

    fn port_scan_event(second: i64, score: f64, category: Option<EventCategory>) -> DetectionEvent {
        let mut event = dns_event(
            at(second),
            addr("192.0.2.1"),
            addr("192.0.2.2"),
            category,
            INLINE_POLICY_SENSOR,
        );
        event.detection_model = review_protocol::types::DetectionModel::PortScan;
        event.score = score;
        event
    }

    #[tokio::test]
    async fn score_condition_matches_at_its_threshold_and_not_below() {
        let events = [
            port_scan_event(0, 0.5, Some(EventCategory::Reconnaissance)),
            port_scan_event(1, 0.499_999, Some(EventCategory::Reconnaissance)),
            port_scan_event(2, 0.9, Some(EventCategory::Reconnaissance)),
            // Same score, another detection model.
            dns_event(
                at(3),
                addr("192.0.2.1"),
                addr("192.0.2.2"),
                Some(EventCategory::Reconnaissance),
                INLINE_POLICY_SENSOR,
            ),
        ];
        let scores = scores_of(
            &events,
            "[]",
            "[{ threatCategory: RECONNAISSANCE, detectionModel: PORT_SCAN, score: 0.5, weight: 2.5 }]",
            1.0,
        )
        .await;
        assert_eq!(
            scores,
            [
                serde_json::json!([{ "policyId": "3", "score": 2.5 }]),
                serde_json::Value::Null,
                serde_json::json!([{ "policyId": "3", "score": 2.5 }]),
                serde_json::Value::Null,
            ]
        );
    }

    #[tokio::test]
    async fn null_threat_category_matches_only_uncategorized_and_weight_defaults_to_one() {
        let events = [
            port_scan_event(0, 0.5, None),
            port_scan_event(1, 0.5, Some(EventCategory::Reconnaissance)),
        ];
        let scores = scores_of(
            &events,
            "[]",
            "[{ threatCategory: null, detectionModel: PORT_SCAN, score: 0.1 }]",
            0.5,
        )
        .await;
        assert_eq!(
            scores,
            [
                serde_json::json!([{ "policyId": "3", "score": 1.0 }]),
                serde_json::Value::Null,
            ]
        );
    }

    #[tokio::test]
    async fn sysmon_packet_attr_matches_a_sysmon_body() {
        let body = |process_id| raw_event::ProcessCreate {
            agent_name: "agent".to_string(),
            agent_id: "agent-1".to_string(),
            process_guid: "{guid}".to_string(),
            process_id,
            image: "C:\\Windows\\cmd.exe".to_string(),
            file_version: String::new(),
            description: String::new(),
            product: String::new(),
            company: String::new(),
            original_file_name: String::new(),
            command_line: "cmd.exe".to_string(),
            current_directory: String::new(),
            user: "user".to_string(),
            logon_guid: String::new(),
            logon_id: 0,
            terminal_session_id: 0,
            integrity_level: String::new(),
            hashes: Vec::new(),
            parent_process_guid: String::new(),
            parent_process_id: 0,
            parent_image: String::new(),
            parent_command_line: String::new(),
            parent_user: String::new(),
            endpoint: None,
            logon_id_full: None,
        };
        let events = [42, 43].map(|process_id| {
            raw_event(
                at(i64::from(process_id)),
                INLINE_POLICY_SENSOR,
                RawEventKind::ProcessCreate,
                RawEventBody::ProcessCreate(body(process_id)),
                Detail::NonBrowser,
            )
        });
        let scores = scores_of(
            &events,
            r#"[{
                rawEventKind: PROCESS_CREATE
                attrName: "Process ID"
                valueKind: U_INTEGER
                cmpKind: EQUAL
                firstValue: [42]
                weight: 1.0
            }]"#,
            "[]",
            0.5,
        )
        .await;
        assert_eq!(
            scores,
            [
                serde_json::json!([{ "policyId": "3", "score": 1.0 }]),
                serde_json::Value::Null,
            ]
        );
    }

    #[tokio::test]
    async fn packet_attr_never_matches_a_subject_target() {
        let raw = raw_event(
            at(0),
            INLINE_POLICY_SENSOR,
            RawEventKind::Conn,
            RawEventBody::Conn(conn_body(addr("192.0.2.1"), addr("192.0.2.2"))),
            Detail::TorExitNode,
        );
        // A subject event of the same raw event kind, which has no body to
        // read the attribute from.
        let subject = subject_event(
            at(1),
            Some(INLINE_POLICY_SENSOR),
            PrimarySubject::Host {
                ip: addr("192.0.2.1"),
                role: ThreatRole::Actor,
            },
            Vec::new(),
            Detail::TorExitNode,
        );
        assert_eq!(subject.raw_event_kind, RawEventKind::Conn);
        let scores = scores_of(
            &[raw, subject],
            r#"[{
                rawEventKind: CONN
                attrName: "Protocol Number"
                valueKind: U_INTEGER
                cmpKind: EQUAL
                firstValue: [6]
                weight: 1.0
            }]"#,
            "[]",
            0.5,
        )
        .await;
        assert_eq!(
            scores,
            [
                serde_json::json!([{ "policyId": "3", "score": 1.0 }]),
                serde_json::Value::Null,
            ]
        );
    }
}
