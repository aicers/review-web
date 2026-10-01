pub(super) mod response;

use async_graphql::{Enum, InputObject};
use review_database as database;
use serde::Deserialize;

use super::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct TriageResponseQuery;

#[derive(Default)]
pub(super) struct TriageResponseMutation;

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize)]
#[graphql(remote = "database::RawEventKind")]
pub enum RawEventKind {
    Bootp,
    Conn,
    Dhcp,
    Dns,
    Ftp,
    Http,
    Kerberos,
    Ldap,
    Log,
    Mqtt,
    Network,
    Nfs,
    Ntlm,
    Radius,
    Rdp,
    Smb,
    Smtp,
    Ssh,
    Tls,
    Window,
    DceRpc,
}

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
    Blacklist,
    Whitelist,
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

#[derive(Clone, InputObject)]
pub(super) struct ConfidenceInput {
    threat_category: Option<ThreatCategory>,
    threat_kind: String,
    confidence: f64,
    weight: Option<f64>,
}

impl From<&ConfidenceInput> for database::Confidence {
    fn from(c: &ConfidenceInput) -> Self {
        Self {
            threat_category: c.threat_category.map(Into::into),
            threat_kind: c.threat_kind.clone(),
            confidence: c.confidence,
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
    use crate::graphql::TestSchema;

    /// Runs `eventListWithTriage` with a single inline policy built from the
    /// given `packetAttr` and `confidence` lists.
    async fn event_list_with_inline_policy(
        schema: &TestSchema,
        packet_attr: &str,
        confidence: &str,
    ) -> async_graphql::Response {
        let query = format!(
            r"{{
                eventListWithTriage(
                    filter: {{}}
                    triage: {{
                        policies: [{{
                            id: 0
                            packetAttr: {packet_attr}
                            confidence: {confidence}
                            response: []
                        }}]
                    }}
                    first: 1
                ) {{
                    totalCount
                }}
            }}"
        );
        schema.execute_as_system_admin(&query).await
    }

    #[tokio::test]
    async fn dce_rpc_raw_event_kind_accepted_in_inline_policy() {
        let schema = TestSchema::new().await;

        // Exercises the remote enum conversions used by PacketAttrInput.
        let res = event_list_with_inline_policy(
            &schema,
            r#"[{
                rawEventKind: DCE_RPC
                attrName: "Presentation Context ID"
                valueKind: U_INTEGER
                cmpKind: EQUAL
                firstValue: [1]
                weight: 1.0
            }]"#,
            "[]",
        )
        .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn inline_policy_accepts_null_threat_category() {
        let schema = TestSchema::new().await;

        let res = event_list_with_inline_policy(
            &schema,
            "[]",
            r#"[{ threatCategory: null, threatKind: "Unspecified", confidence: 0.25 }]"#,
        )
        .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn inline_policy_rejects_missing_threat_kind() {
        let schema = TestSchema::new().await;

        // threatKind is required even when threatCategory is null.
        let res = event_list_with_inline_policy(
            &schema,
            "[]",
            "[{ threatCategory: null, confidence: 0.25 }]",
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
                    name: "p", triageExclusionId: [], packetAttr: [], confidence: [], response: []
                )
            }"#,
            r#"mutation {
                updateTriagePolicy(
                    id: "0"
                    old: {
                        name: "p", triageExclusionId: [], packetAttr: [], confidence: [], response: []
                    }
                    new: {
                        name: "q", triageExclusionId: [], packetAttr: [], confidence: [], response: []
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
}
