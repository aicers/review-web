//! The GraphQL type of a stored detection event, and of its target.

use std::net::IpAddr;

use async_graphql::{Enum, ID, Object, SimpleObject, StringNumber, Union};
use review_database::{self as database, StoredDetectionEvent};
use review_protocol::types as protocol;

use super::{TriageScore, body::RawEventBody, detail::Detail, opaque_event_id};
use crate::graphql::{
    clustering_model_type::ClusteringModelTypeRef,
    filter::{DetectionModel, RawEventKind},
    model::ModelInstance,
    timestamp::Timestamp,
    triage::ThreatCategory,
};

/// The role a primary subject plays in a threat.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "protocol::ThreatRole")]
pub(in crate::graphql) enum ThreatRole {
    Actor,
    Target,
}

/// The side of the traffic an address was observed on.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "protocol::EndpointRole")]
pub(in crate::graphql) enum EndpointRole {
    Source,
    Destination,
}

/// A detection event as stored: what a detection engine reported, and what
/// was recorded about it when it was received.
pub(super) struct DetectionEvent {
    key: i128,
    record: StoredDetectionEvent,
    triage_scores: Option<Vec<database::event::TriageScore>>,
}

impl DetectionEvent {
    pub(super) fn new(key: i128, record: StoredDetectionEvent) -> Self {
        Self {
            key,
            record,
            triage_scores: None,
        }
    }

    pub(super) fn with_triage_scores(
        key: i128,
        record: StoredDetectionEvent,
        triage_scores: Option<Vec<database::event::TriageScore>>,
    ) -> Self {
        Self {
            key,
            record,
            triage_scores,
        }
    }
}

#[Object]
impl DetectionEvent {
    /// The opaque identifier of the event.
    async fn id(&self) -> ID {
        opaque_event_id(self.key)
    }

    /// When the event happened.
    async fn time(&self) -> Timestamp {
        self.record.event().time.into()
    }

    /// The name of the sensor the event is about, or null if it was stored
    /// without one.
    async fn sensor(&self) -> Option<&str> {
        self.record.event().sensor.as_deref()
    }

    /// The detection model that produced the event.
    async fn detection_model(&self) -> DetectionModel {
        self.record.event().detection_model.into()
    }

    /// The kind of the raw event the event is about.
    async fn raw_event_kind(&self) -> RawEventKind {
        self.record.event().raw_event_kind.into()
    }

    /// The threat category of the event, or null if it has none.
    async fn category(&self) -> Option<ThreatCategory> {
        self.record
            .event()
            .category
            .map(|category| database::EventCategory::from(category).into())
    }

    /// What the event is about: a raw event, or a subject observed over a
    /// time window.
    async fn target(&self) -> Target<'_> {
        self.record.event().into()
    }

    /// The score the detection model gave the event.
    async fn score(&self) -> f64 {
        self.record.event().score
    }

    /// What the detection model found.
    async fn detail(&self) -> Detail<'_> {
        (&self.record.event().detail).into()
    }

    /// The engine instance that sent the event.
    async fn engine_instance(&self) -> ModelInstance {
        (&self.record.stamp().engine_instance).into()
    }

    /// The clustering model the event is about, if one.
    async fn clustering_model_id(&self) -> Option<ID> {
        self.record
            .stamp()
            .clustering_model_id
            .map(|id| ID(id.to_string()))
    }

    /// When the model that made the detection was trained, if known.
    async fn trained_at(&self) -> Option<Timestamp> {
        self.record.stamp().trained_at.map(Into::into)
    }

    /// The clustering model type the model that made the detection had when
    /// the event was received, as recorded with the event, or null if none
    /// was recorded, as for every event of the Semi-supervised Engine.
    ///
    /// It is not looked up from the model's current record, so a later
    /// retrain of the model as another type does not change it.
    async fn clustering_model_type(&self) -> Option<ClusteringModelTypeRef<'_>> {
        self.record
            .stamp()
            .clustering_model_type
            .as_ref()
            .map(Into::into)
    }

    /// The version of the engine installed when the event was received, or
    /// null if neither its version nor its commit was recorded.
    async fn engine_version(&self) -> Option<EngineVersion<'_>> {
        let stamp = self.record.stamp();
        if stamp.installed_version.is_none() && stamp.installed_commit.is_none() {
            return None;
        }
        Some(EngineVersion {
            version: stamp.installed_version.as_deref(),
            commit: stamp.installed_commit.as_deref(),
        })
    }

    /// The revision of the engine configuration applied to the engine
    /// instance when the event was received, or null if none was applied.
    ///
    /// This is not necessarily the configuration the engine used to produce
    /// the event.
    async fn config_revision(&self) -> Option<StringNumber<u64>> {
        self.record.stamp().config_revision.map(StringNumber)
    }

    /// The country code stored for each endpoint address of the event.
    ///
    /// For a raw event, the body's originator address comes before its
    /// responder address, and a body without both, such as a Sysmon body,
    /// has none. For a subject, the IP of a host subject comes first, then
    /// each related IP in order.
    async fn endpoint_countries(&self) -> Vec<EndpointCountry> {
        self.record
            .country_codes()
            .map(|(ip, country)| EndpointCountry { ip, country })
            .collect()
    }

    /// The scores of the inline triage policies the event qualifies for, or
    /// null if none was given or none qualifies.
    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect())
    }
}

/// The version of the engine installed when an event was received.
#[derive(SimpleObject)]
pub(super) struct EngineVersion<'a> {
    /// The installed version, if recorded.
    version: Option<&'a str>,
    /// The installed commit, if recorded.
    commit: Option<&'a str>,
}

/// An endpoint address of a detection event and its stored country code.
pub(super) struct EndpointCountry {
    ip: IpAddr,
    country: [u8; 2],
}

#[Object]
impl EndpointCountry {
    /// The endpoint address.
    async fn ip(&self) -> String {
        self.ip.to_string()
    }

    /// The two-letter country code stored for the address. `"ZZ"` if the
    /// country could not be determined, and `"XX"` if no country
    /// information was recorded.
    async fn country(&self) -> &str {
        country_code(&self.country)
    }
}

/// What a detection event is about.
#[derive(Union)]
pub(super) enum Target<'a> {
    RawEvent(RawEventTarget<'a>),
    Subject(SubjectTarget<'a>),
}

impl<'a> From<&'a protocol::DetectionEvent> for Target<'a> {
    fn from(event: &'a protocol::DetectionEvent) -> Self {
        match &event.target {
            protocol::Target::RawEvent { time, body } => {
                Self::RawEvent(RawEventTarget { time: *time, body })
            }
            protocol::Target::Subject {
                primary,
                related_ips,
                window,
            } => Self::Subject(SubjectTarget {
                sensor: event.sensor.as_deref(),
                primary,
                related_ips,
                window,
            }),
        }
    }
}

/// A raw event a detection event is about.
pub(super) struct RawEventTarget<'a> {
    time: jiff::Timestamp,
    body: &'a protocol::RawEventBody,
}

#[Object]
impl<'a> RawEventTarget<'a> {
    /// The time of the raw event, its Giganto key timestamp.
    async fn time(&self) -> Timestamp {
        self.time.into()
    }

    /// The body of the raw event.
    async fn body(&self) -> RawEventBody<'a> {
        self.body.into()
    }
}

/// A subject a detection event is about, observed over a time window.
pub(super) struct SubjectTarget<'a> {
    /// The sensor of the detection event, which a sensor subject names.
    sensor: Option<&'a str>,
    primary: &'a protocol::PrimarySubject,
    related_ips: &'a [protocol::RelatedIp],
    window: &'a protocol::TimeWindow,
}

#[Object]
impl<'a> SubjectTarget<'a> {
    /// The subject the event is primarily about.
    async fn primary(&self) -> PrimarySubject<'a> {
        match self.primary {
            protocol::PrimarySubject::Host { ip, role } => PrimarySubject::Host(HostSubject {
                ip: *ip,
                role: (*role).into(),
            }),
            protocol::PrimarySubject::Cluster {
                clustering_model,
                cluster_id,
            } => PrimarySubject::Cluster(ClusterSubject {
                clustering_model: ID(clustering_model.to_string()),
                cluster_id: ID(cluster_id.to_string()),
            }),
            protocol::PrimarySubject::Sensor => PrimarySubject::Sensor(SensorSubject {
                sensor: self.sensor,
            }),
            protocol::PrimarySubject::Network {
                customer,
                name,
                role,
            } => PrimarySubject::Network(NetworkSubject {
                customer: ID(customer.to_string()),
                name,
                role: (*role).into(),
            }),
        }
    }

    /// The other addresses involved, each with the side it was observed on.
    async fn related_ips(&self) -> Vec<RelatedIp<'a>> {
        self.related_ips.iter().map(RelatedIp).collect()
    }

    /// The time window the subject was observed over.
    async fn window(&self) -> TimeWindow<'a> {
        TimeWindow(self.window)
    }
}

/// The subject a detection event is primarily about.
#[derive(Union)]
pub(super) enum PrimarySubject<'a> {
    Host(HostSubject),
    Cluster(ClusterSubject),
    Sensor(SensorSubject<'a>),
    Network(NetworkSubject<'a>),
}

/// A host, named by its IP address.
pub(super) struct HostSubject {
    ip: IpAddr,
    role: ThreatRole,
}

#[Object]
impl HostSubject {
    /// The IP address of the host.
    async fn ip(&self) -> String {
        self.ip.to_string()
    }

    /// The role the host plays in the threat.
    async fn role(&self) -> ThreatRole {
        self.role
    }
}

/// A cluster of a clustering model.
#[derive(SimpleObject)]
pub(super) struct ClusterSubject {
    /// The clustering model the cluster belongs to.
    clustering_model: ID,
    /// The cluster within its clustering model.
    cluster_id: ID,
}

/// The sensor of the detection event.
#[derive(SimpleObject)]
pub(super) struct SensorSubject<'a> {
    /// The sensor of the detection event, null only for an event stored
    /// without one.
    sensor: Option<&'a str>,
}

/// A network of a customer.
#[derive(SimpleObject)]
pub(super) struct NetworkSubject<'a> {
    /// The customer the network belongs to.
    customer: ID,
    /// The name of the network.
    name: &'a str,
    /// The role the network plays in the threat.
    role: ThreatRole,
}

/// An address related to a subject.
pub(super) struct RelatedIp<'a>(&'a protocol::RelatedIp);

#[Object]
impl RelatedIp<'_> {
    /// The address.
    async fn ip(&self) -> String {
        self.0.ip.to_string()
    }

    /// The side of the traffic the address was observed on.
    async fn role(&self) -> EndpointRole {
        self.0.role.into()
    }
}

/// A time window, from `start` to `end`.
pub(super) struct TimeWindow<'a>(&'a protocol::TimeWindow);

#[Object]
impl TimeWindow<'_> {
    /// The start of the window.
    async fn start(&self) -> Timestamp {
        self.0.start.into()
    }

    /// The end of the window.
    async fn end(&self) -> Timestamp {
        self.0.end.into()
    }
}

/// Returns the two-letter country code a stored code spells, or `"ZZ"` if it
/// is not valid UTF-8.
pub(super) fn country_code(code: &[u8; 2]) -> &str {
    std::str::from_utf8(code).unwrap_or("ZZ")
}
