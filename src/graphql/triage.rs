#![allow(deprecated)]

mod exclusion_reason;
mod policy;
pub(super) mod response;

use async_graphql::{Enum, ID, InputObject, Object, Result};
use chrono::{DateTime, Utc};
pub(crate) use exclusion_reason::{TriageExclusionReasonMutation, TriageExclusionReasonQuery};
use review_database as database;
use serde::Deserialize;

use super::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct TriagePolicyQuery;

#[derive(Default)]
pub(super) struct TriagePolicyMutation;

#[derive(Default)]
pub(super) struct TriageResponseQuery;

#[derive(Default)]
pub(super) struct TriageResponseMutation;

pub(super) struct TriagePolicy {
    inner: database::TriagePolicy,
}

#[Object]
impl TriagePolicy {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn triage_exclusion_id(&self) -> Vec<ID> {
        self.inner
            .triage_exclusion_id
            .iter()
            .map(|id| ID::from(id.to_string()))
            .collect()
    }

    async fn packet_attr(&self) -> Vec<PacketAttr<'_>> {
        self.inner.packet_attr.iter().map(Into::into).collect()
    }

    async fn confidence(&self) -> Vec<Confidence<'_>> {
        self.inner.confidence.iter().map(Into::into).collect()
    }

    async fn response(&self) -> Vec<Response<'_>> {
        self.inner.response.iter().map(Into::into).collect()
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }

    async fn customer_id(&self) -> Option<ID> {
        self.inner.customer_id.map(|id| ID::from(id.to_string()))
    }
}

impl From<database::TriagePolicy> for TriagePolicy {
    fn from(inner: database::TriagePolicy) -> Self {
        Self { inner }
    }
}

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
    Rdp,
    Smb,
    Smtp,
    Ssh,
    Tls,
    Window,
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

struct PacketAttr<'a> {
    inner: &'a database::PacketAttr,
}

#[Object]
impl PacketAttr<'_> {
    async fn raw_event_kind(&self) -> RawEventKind {
        self.inner.raw_event_kind.into()
    }

    async fn attr_name(&self) -> &str {
        &self.inner.attr_name
    }

    async fn value_kind(&self) -> ValueKind {
        self.inner.value_kind.into()
    }

    async fn cmp_kind(&self) -> AttrCmpKind {
        self.inner.cmp_kind.into()
    }

    async fn first_value(&self) -> &[u8] {
        &self.inner.first_value
    }

    async fn second_value(&self) -> Option<&[u8]> {
        self.inner.second_value.as_deref()
    }

    async fn weight(&self) -> Option<f64> {
        self.inner.weight
    }
}

impl<'a> From<&'a database::PacketAttr> for PacketAttr<'a> {
    fn from(inner: &'a database::PacketAttr) -> Self {
        Self { inner }
    }
}

struct Confidence<'a> {
    inner: &'a database::Confidence,
}

#[Object]
impl Confidence<'_> {
    async fn threat_category(&self) -> ThreatCategory {
        self.inner.threat_category.into()
    }

    async fn threat_kind(&self) -> &str {
        &self.inner.threat_kind
    }

    async fn confidence(&self) -> f64 {
        self.inner.confidence
    }

    async fn weight(&self) -> Option<f64> {
        self.inner.weight
    }
}

impl<'a> From<&'a database::Confidence> for Confidence<'a> {
    fn from(inner: &'a database::Confidence) -> Self {
        Self { inner }
    }
}

struct Response<'a> {
    inner: &'a database::Response,
}

#[Object]
impl Response<'_> {
    async fn minimum_score(&self) -> f64 {
        self.inner.minimum_score
    }

    async fn kind(&self) -> ResponseKind {
        self.inner.kind.into()
    }
}

impl<'a> From<&'a database::Response> for Response<'a> {
    fn from(inner: &'a database::Response) -> Self {
        Self { inner }
    }
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
    threat_category: ThreatCategory,
    threat_kind: String,
    confidence: f64,
    weight: Option<f64>,
}

impl From<&ConfidenceInput> for database::Confidence {
    fn from(c: &ConfidenceInput) -> Self {
        Self {
            threat_category: c.threat_category.into(),
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

#[derive(Clone, InputObject)]
pub(super) struct TriagePolicyInput {
    pub name: String,
    pub triage_exclusion_id: Vec<ID>,
    pub packet_attr: Vec<PacketAttrInput>,
    pub confidence: Vec<ConfidenceInput>,
    pub response: Vec<ResponseInput>,
    pub customer_id: Option<ID>,
}

impl TryFrom<TriagePolicyInput> for database::TriagePolicyUpdate {
    type Error = anyhow::Error;

    fn try_from(input: TriagePolicyInput) -> Result<Self, Self::Error> {
        let triage_exclusion_id = input
            .triage_exclusion_id
            .iter()
            .map(|id| id.as_str().parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow::anyhow!("invalid triage exclusion id"))?;
        Ok(Self {
            name: input.name,
            triage_exclusion_id,
            packet_attr: input.packet_attr.iter().map(Into::into).collect(),
            confidence: input.confidence.iter().map(Into::into).collect(),
            response: input.response.iter().map(Into::into).collect(),
            customer_id: input
                .customer_id
                .map(|id| id.as_str().parse::<u32>())
                .transpose()
                .map_err(|_| anyhow::anyhow!("invalid customer id"))?,
        })
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

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_triage_policy() {
        let schema = TestSchema::new().await;

        // Prepare triage exclusion reasons
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason A"
                        description: "reason a"
                        ipAddress: {
                            hosts: ["1.1.1.1"]
                            networks: []
                            ranges: []
                        }
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason B"
                        description: "reason b"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "1"}"#
        );

        let res = schema
            .execute_as_system_admin(r"{triagePolicyList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r"{triagePolicyList: {totalCount: 0}}");

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriagePolicy(
                        name: "Triage 1"
                        triageExclusionId: ["0"]
                        packetAttr: [{
                            rawEventKind: CONN
                            attrName: "Packets Received"
                            valueKind: STRING
                            cmpKind: CONTAIN
                            firstValue: [4, 80, 79, 83, 84]
                            weight: 0.5
                        }, {
                            rawEventKind: CONN
                            attrName: "Packets Received"
                            valueKind: INTEGER
                            cmpKind: GREATER_OR_EQUAL
                            firstValue: [251, 88, 2]
                            secondValue: [251, 232, 3]
                            weight: 0.5
                        }]
                        confidence: [{
                            threatCategory: COMMAND_AND_CONTROL
                            threatKind: "DNS Covert"
                            confidence: 0.5
                            weight: 0.5
                        }, {
                            threatCategory: COMMAND_AND_CONTROL
                            threatKind: "HTTP Covert"
                            confidence: 0.5
                            weight: 0.5
                        }]
                        response: [{
                            minimumScore: 0.5
                            kind: MANUAL,
                        }]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Triage 1"
                            triageExclusionId: ["0"]
                            packetAttr: [{
                                rawEventKind: CONN
                                attrName: "Packets Received"
                                valueKind: STRING
                                cmpKind: CONTAIN
                                firstValue: [4, 80, 79, 83, 84]
                                weight: 0.5
                            }, {
                                rawEventKind: CONN
                                attrName: "Packets Received"
                                valueKind: INTEGER
                                cmpKind: GREATER_OR_EQUAL
                                firstValue: [251, 88, 2]
                                secondValue: [251, 232, 3]
                                weight: 0.5
                            }]
                            confidence: [{
                                threatCategory: COMMAND_AND_CONTROL
                                threatKind: "DNS Covert"
                                confidence: 0.5
                                weight: 0.5
                            }, {
                                threatCategory: COMMAND_AND_CONTROL
                                threatKind: "HTTP Covert"
                                confidence: 0.5
                                weight: 0.5
                            }]
                            response: [{
                                minimumScore: 0.5
                                kind: MANUAL,
                            }]
                        }
                        new: {
                            name: "Triage 2"
                            triageExclusionId: ["1"]
                            packetAttr: [{
                                rawEventKind: CONN
                                attrName: "Packets Received"
                                valueKind: STRING
                                cmpKind: CONTAIN
                                firstValue: [4, 80, 79, 83, 84]
                                weight: 0.5
                            }, {
                                rawEventKind: CONN
                                attrName: "Packets Received"
                                valueKind: INTEGER
                                cmpKind: GREATER
                                firstValue: [251, 88, 2]
                                secondValue: [251, 232, 3]
                                weight: 0.5
                            }]
                            confidence: [{
                                threatCategory: COMMAND_AND_CONTROL
                                threatKind: "DNS Covert"
                                confidence: 0.5
                                weight: 0.5
                            }, {
                                threatCategory: COMMAND_AND_CONTROL
                                threatKind: "HTTP Covert"
                                confidence: 0.5
                                weight: 0.5
                            }]
                            response: [{
                                minimumScore: 0.5
                                kind: MANUAL,
                            }]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r"
                query {
                    triagePolicyList(first: 10) {
                        nodes {
                            name
                        }
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicyList: {nodes: [{name: "Triage 2"}]}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeTriagePolicies(ids: ["0"])
                }"#,
            )
            .await;
        let removed = res.data.to_string();
        assert!(
            removed.contains("Triage 2"),
            "Unexpected removeTriagePolicies payload: {removed}"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_triage_policy_filter_by_customer() {
        let schema = TestSchema::new().await;

        // Prepare customers for validation
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "2"}"#);

        // exclusion reason to satisfy validation
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason Filter"
                        description: "filter reason"
                        ipAddress: {
                            hosts: ["10.0.0.1"]
                            networks: []
                            ranges: []
                        }
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // global policy (customer_id None)
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriagePolicy(
                        name: "Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // customer-specific policy
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriagePolicy(
                        name: "Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "1"}"#);

        // customer_id = 1 should include both (None and 1)
        let res = schema
            .execute_as_system_admin(
                r#"
                {
                    triagePolicyList(first: 10, customerId: "1") {
                        totalCount
                        nodes { name customerId }
                    }
                }"#,
            )
            .await;
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], 2);
        let names: Vec<String> = json["triagePolicyList"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"Global Policy".to_string()));
        assert!(names.contains(&"Customer Policy".to_string()));

        // customer_id = 2 should include only global
        let res = schema
            .execute_as_system_admin(
                r#"
                {
                    triagePolicyList(first: 10, customerId: "2") {
                        totalCount
                        nodes { name }
                    }
                }"#,
            )
            .await;
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], 1);
        assert_eq!(
            json["triagePolicyList"]["nodes"][0]["name"]
                .as_str()
                .unwrap(),
            "Global Policy"
        );
    }

    #[tokio::test]
    async fn test_triage_response() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r"{triageResponseList{totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{triageResponseList: {totalCount: 0}}"
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageResponse(
                        sensor: "sensor1"
                        time: "2023-02-14 14:54:46.083902898 +00:00"
                        tagIds: [1, 2, 3]
                        remarks: "Hello World"
                    )
                }
                "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriageResponse: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateTriageResponse(
                        id: "0"
                        old: {
                            key: [
                                115,
                                101,
                                110,
                                115,
                                111,
                                114,
                                49,
                                23,
                                67,
                                184,
                                160,
                                145,
                                75,
                                221,
                                178
                            ]
                            tagIds:[1, 2, 3]
                            remarks:"Hello World"
                        }
                        new: {
                            key: [
                                115,
                                101,
                                110,
                                115,
                                111,
                                114,
                                49,
                                23,
                                67,
                                184,
                                160,
                                145,
                                75,
                                221,
                                178
                            ]
                            tagIds:[2, 3]
                        }
                    )
                }
                "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTriageResponse: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r"
                mutation {
                    removeTriageResponses(ids: [0])
                }
                ",
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTriageResponses: ["0"]}"#);
    }
}
