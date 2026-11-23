//! Synthetic detection events for tests.

use std::net::IpAddr;

use jiff::Timestamp;
use review_database::{DetectionEventStamp, EventDb, ModelInstance};
use review_protocol::types::{
    Detail, DetectionEvent, EndpointRole, EventCategory, PrimarySubject, RawEventBody,
    RawEventKind, RelatedIp, Target, TimeWindow, raw_event,
};

/// The score a synthetic event gets unless a test sets another.
pub(crate) const DEFAULT_SCORE: f64 = 0.8;

/// Stores a detection event with [`stamp`].
pub(crate) trait PutEvent {
    /// Stores `event` with the default stamp and returns its key.
    fn put_event(&self, event: &DetectionEvent) -> anyhow::Result<i128>;
}

impl PutEvent for EventDb<'_> {
    fn put_event(&self, event: &DetectionEvent) -> anyhow::Result<i128> {
        self.put(event, &stamp())
    }
}

/// Returns a stamp naming engine instance `semi-supervised` on node 1, with
/// nothing else recorded.
pub(crate) fn stamp() -> DetectionEventStamp {
    DetectionEventStamp {
        engine_instance: ModelInstance {
            node_id: 1,
            agent_key: "semi-supervised".to_string(),
        },
        clustering_model_id: None,
        trained_at: None,
        installed_version: None,
        installed_commit: None,
        config_revision: None,
        clustering_model_type: None,
    }
}

/// Returns a TCP connection raw event body from `orig` to `resp`.
pub(crate) fn conn_body(orig: IpAddr, resp: IpAddr) -> raw_event::Conn {
    raw_event::Conn {
        orig_addr: orig,
        orig_port: 46378,
        resp_addr: resp,
        resp_port: 80,
        proto: 6,
        conn_state: "SF".to_string(),
        start_time: 0,
        duration: 0,
        service: "http".to_string(),
        orig_bytes: 0,
        resp_bytes: 0,
        orig_pkts: 0,
        resp_pkts: 0,
        orig_l2_bytes: 0,
        resp_l2_bytes: 0,
    }
}

/// Returns a DNS raw event body from `orig` to `resp`, querying `domain`.
pub(crate) fn dns_body(orig: IpAddr, resp: IpAddr) -> raw_event::Dns {
    raw_event::Dns {
        orig_addr: orig,
        orig_port: 10000,
        resp_addr: resp,
        resp_port: 53,
        proto: 17,
        start_time: 0,
        duration: 0,
        orig_pkts: 0,
        resp_pkts: 0,
        orig_l2_bytes: 0,
        resp_l2_bytes: 0,
        query: "domain".to_string(),
        answer: Vec::new(),
        trans_id: 0,
        rtt: 0,
        qclass: 0,
        qtype: 0,
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: false,
        ra_flag: false,
        ttl: Vec::new(),
    }
}

/// Returns a detection event of `detail`'s model about the raw event `body` of
/// `kind`, seen by `sensor` at `time`.
pub(crate) fn raw_event(
    time: Timestamp,
    sensor: &str,
    kind: RawEventKind,
    body: RawEventBody,
    detail: Detail,
) -> DetectionEvent {
    DetectionEvent {
        time,
        sensor: Some(sensor.to_string()),
        detection_model: detail.detection_model(),
        raw_event_kind: kind,
        category: None,
        target: Target::RawEvent { time, body },
        score: DEFAULT_SCORE,
        detail,
    }
}

/// Returns a `DnsCovertChannel` event about a DNS raw event from `orig` to
/// `resp`.
pub(crate) fn dns_event(
    time: Timestamp,
    orig: IpAddr,
    resp: IpAddr,
    category: Option<EventCategory>,
    sensor: &str,
) -> DetectionEvent {
    let mut event = raw_event(
        time,
        sensor,
        RawEventKind::Dns,
        RawEventBody::Dns(dns_body(orig, resp)),
        Detail::DnsCovertChannel,
    );
    event.category = category;
    event
}

/// Returns a detection event of `detail`'s model about `primary` and
/// `related_ips`, observed over the second starting at `time`.
pub(crate) fn subject_event(
    time: Timestamp,
    sensor: Option<&str>,
    primary: PrimarySubject,
    related_ips: Vec<RelatedIp>,
    detail: Detail,
) -> DetectionEvent {
    DetectionEvent {
        time,
        sensor: sensor.map(ToString::to_string),
        detection_model: detail.detection_model(),
        raw_event_kind: RawEventKind::Conn,
        category: None,
        target: Target::Subject {
            primary,
            related_ips,
            window: TimeWindow {
                start: time,
                end: time + jiff::SignedDuration::from_secs(1),
            },
        },
        score: DEFAULT_SCORE,
        detail,
    }
}

/// Returns a related IP.
pub(crate) fn related(ip: &str, role: EndpointRole) -> RelatedIp {
    RelatedIp {
        ip: ip.parse().expect("a test address"),
        role,
    }
}
