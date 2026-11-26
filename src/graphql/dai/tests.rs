//! Tests of the device identification API, and the stores, sensors and
//! observations they need.
//!
//! Observations reach review-database the way an agent sends them: the
//! cursors are read, each slot is sent as one batch, and the pending
//! observations are applied. review-database takes the time of its own
//! writes from the clock, and device identification collects from the time
//! it was turned on, so the observations are timed from the slot the first
//! cursor read opens, and the requests are made "now" at a time a test
//! chooses with [`RequestTime`].

mod access;
mod collection;
mod devices;
mod operator;
mod policy;
mod resolve;
mod settings;
mod sites;

use std::{collections::BTreeMap, net::IpAddr};

use review_database::{
    DAI_APPLY_DEFAULT_MAX_COUNT, DaiSettingsUpdate, DaiStoreOutcome, Store, dai_network_digest,
};
use review_protocol::types::{
    DaiDhcpMsg, DaiObservation, DaiObservationBatch, DaiObservationBody,
    DaiObservationKind as Kind, DaiSide,
};
use serde_json::Value;

use super::RequestTime;
use crate::graphql::{
    Role, TestSchema,
    time_series_generation_test_support::{insert_generator_node, sensor_name},
};

pub(super) const NS: i64 = 1_000_000_000;
pub(super) const MINUTE: i64 = 60 * NS;
pub(super) const HOUR: i64 = 60 * MINUTE;
pub(super) const DAY: i64 = 24 * HOUR;
/// The length of a slot.
pub(super) const SLOT: i64 = 5 * MINUTE;
/// The customer most tests use.
pub(super) const CUSTOMER: u32 = 1;
/// Another customer.
pub(super) const OTHER: u32 = 2;
/// The Kerberos realm [`enable`] confirms.
pub(super) const REALM: &str = "CORP.EXAMPLE";
/// The DHCP server of the observations.
const SERVER: &str = "10.0.0.254";
/// The lease time of an ACK from [`ack`], in seconds; a binding it starts is
/// in effect for twice as long after its last ACK.
pub(super) const LEASE_SECS: u32 = 300;

/// Returns the address `text`.
pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// Returns the RFC 3339 text of `nanos`.
pub(super) fn rfc3339(nanos: i64) -> String {
    jiff::Timestamp::from_nanosecond(i128::from(nanos))
        .unwrap()
        .to_string()
}

/// Returns the MAC `n`, a locally administered unicast address, as bytes.
pub(super) fn mac(n: u8) -> Vec<u8> {
    vec![0x02, 0, 0, 0, 0, n]
}

/// Returns the MAC `n` as review-database lists it.
pub(super) fn mac_text(n: u8) -> String {
    format!("02:00:00:00:00:{n:02x}")
}

/// Returns the current time, in nanoseconds since the UNIX epoch.
pub(super) fn wall_clock() -> i64 {
    i64::try_from(jiff::Timestamp::now().as_nanosecond()).unwrap()
}

/// A raw key and value.
type RawRow = (Box<[u8]>, Box<[u8]>);

/// An observation and the time it was seen.
pub(super) struct Seen {
    first: i64,
    last: i64,
    body: DaiObservationBody,
}

impl Seen {
    fn kind(&self) -> Kind {
        match self.body {
            DaiObservationBody::DhcpLease { .. } => Kind::DhcpLease,
            DaiObservationBody::DhcpServer { .. } => Kind::DhcpServer,
            DaiObservationBody::Kerberos { .. } => Kind::Kerberos,
            DaiObservationBody::Ntlm { .. } => Kind::Ntlm,
            DaiObservationBody::Service { .. } => Kind::Service,
            DaiObservationBody::SoftwareString { .. } => Kind::SoftwareString,
            DaiObservationBody::DnsName { .. } => Kind::DnsName,
            DaiObservationBody::IpActivity { .. } => Kind::IpActivity,
        }
    }
}

fn lease(time: i64, msg: DaiDhcpMsg, addr: &str, mac_n: u8, hostname: Option<&str>) -> Seen {
    Seen {
        first: time,
        last: time,
        body: DaiObservationBody::DhcpLease {
            time,
            msg,
            ip: ip(addr),
            chaddr: mac(mac_n),
            xid: 1,
            server_ip: ip(SERVER),
            server_id: Some(ip(SERVER)),
            giaddr: ip("0.0.0.0"),
            client_id: None,
            hostname: hostname.map(ToString::to_string),
            lease_secs: Some(LEASE_SECS),
            subnet_mask: None,
            routers: Vec::new(),
        },
    }
}

/// Returns a DHCP ACK of `addr` to MAC `mac_n` at `time`.
pub(super) fn ack(time: i64, addr: &str, mac_n: u8) -> Seen {
    lease(time, DaiDhcpMsg::Ack, addr, mac_n, None)
}

/// Returns a DHCP ACK of `addr` to MAC `mac_n` at `time` carrying the DHCP
/// hostname `hostname`.
pub(super) fn named_ack(time: i64, addr: &str, mac_n: u8, hostname: &str) -> Seen {
    lease(time, DaiDhcpMsg::Ack, addr, mac_n, Some(hostname))
}

/// Returns a verified Kerberos AS-REP for `cname` under `realm` from `addr`
/// at `time`.
pub(super) fn kerberos(time: i64, addr: &str, cname: &str, realm: &str) -> Seen {
    Seen {
        first: time,
        last: time,
        body: DaiObservationBody::Kerberos {
            client_ip: ip(addr),
            realm: realm.to_string(),
            cname: vec![cname.to_string()],
            sname: vec!["krbtgt".to_string()],
            msg_type: 11,
            accepted: true,
            preauth: 2,
            error_code: None,
        },
    }
}

/// Returns a successful NTLM authentication of `user` in `domain` from
/// workstation `workstation` at `addr` at `time`.
pub(super) fn ntlm(time: i64, addr: &str, user: &str, domain: &str, workstation: &str) -> Seen {
    Seen {
        first: time,
        last: time,
        body: DaiObservationBody::Ntlm {
            ip: ip(addr),
            workstation: workstation.to_string(),
            user: user.to_string(),
            domain: domain.to_string(),
            success: true,
        },
    }
}

/// Returns a TCP service on `port` of `addr` seen at `time`.
pub(super) fn service(time: i64, addr: &str, port: u16) -> Seen {
    Seen {
        first: time,
        last: time,
        body: DaiObservationBody::Service {
            server_ip: ip(addr),
            port,
            proto: 6,
            external_client: false,
        },
    }
}

/// Returns the activity of `addr` from `first` to `last`.
pub(super) fn activity(first: i64, last: i64, addr: &str) -> Seen {
    Seen {
        first,
        last,
        body: DaiObservationBody::IpActivity {
            ip: ip(addr),
            side: DaiSide::Client,
        },
    }
}

/// Writes the settings of `customer`: device account identification on, an
/// inactivity multiplier of 2, an hour without a lease, 180 days of
/// evidence aging and the realm [`REALM`].
pub(super) fn enable(store: &Store, customer: u32) {
    let revision = store.dai_settings(customer).unwrap().revision;
    store
        .set_dai_settings(
            customer,
            revision,
            &DaiSettingsUpdate {
                device_account_identification: true,
                inactivity_multiplier: 2,
                no_lease_inactivity_secs: 3600,
                evidence_aging_secs: 180 * 86_400,
                kerberos_preauth_realms: vec![REALM.to_string()],
            },
        )
        .unwrap();
}

/// Stores the node `host` of `customer` with a Sensor, and returns the
/// sensor's name.
pub(super) fn sensor(store: &Store, host: &str, customer: u32) -> String {
    insert_generator_node(store, host, customer);
    sensor_name(host)
}

/// The agent of one sensor: its read position per kind, and the sends that
/// move it.
pub(super) struct Agent {
    pub(super) sensor: String,
    customer: u32,
    /// The start of the next slot to send, per kind.
    next: BTreeMap<u8, i64>,
    /// The start of the slot the first cursor read opened, which every
    /// observation of a test is timed from.
    pub(super) start: i64,
}

impl Agent {
    /// Reads the cursors of `sensor`, a sensor of `customer` with device
    /// identification on, as an agent starting does.
    pub(super) fn start(store: &Store, sensor: &str, customer: u32) -> Self {
        let cursors = store
            .dai_cursors(&[sensor.to_string()], wall_clock())
            .unwrap();
        let next: BTreeMap<u8, i64> = cursors
            .entries
            .iter()
            .filter(|entry| entry.sensor == sensor)
            .map(|entry| (entry.kind as u8, entry.cursor))
            .collect();
        let start = *next
            .get(&(Kind::DhcpLease as u8))
            .expect("the cursor read creates a cursor of every kind");
        Self {
            sensor: sensor.to_string(),
            customer,
            next,
            start,
        }
    }

    /// Returns the time `minutes` minutes after [`start`](Self::start).
    pub(super) fn at(&self, minutes: i64) -> i64 {
        self.start + minutes * MINUTE
    }

    /// Sends `seen`, each observation in the slot of its first seen time,
    /// every slot of its kind before it that was not sent yet sent empty.
    pub(super) fn send(&mut self, store: &Store, seen: Vec<Seen>) {
        let mut by_kind: BTreeMap<u8, (Kind, BTreeMap<i64, Vec<DaiObservation>>)> = BTreeMap::new();
        for seen in seen {
            let kind = seen.kind();
            let slot = seen.first - seen.first.rem_euclid(SLOT);
            by_kind
                .entry(kind as u8)
                .or_insert_with(|| (kind, BTreeMap::new()))
                .1
                .entry(slot)
                .or_default()
                .push(DaiObservation {
                    first_seen: seen.first,
                    last_seen: seen.last,
                    count: 1,
                    body: seen.body,
                });
        }
        for (kind, slots) in by_kind.into_values() {
            let last = *slots.keys().last().expect("a kind is listed with a slot");
            let mut slots = slots;
            while self.next(kind) <= last {
                let slot = self.next(kind);
                self.send_slot(
                    store,
                    kind,
                    slot,
                    slots.remove(&slot).unwrap_or_default(),
                    None,
                );
            }
        }
    }

    /// Sends every slot of `kinds` not sent yet that starts before `until`,
    /// empty, so their cursors reach `until`.
    pub(super) fn reach(&mut self, store: &Store, kinds: &[Kind], until: i64) {
        for &kind in kinds {
            while self.next(kind) < until {
                let slot = self.next(kind);
                self.send_slot(store, kind, slot, Vec::new(), None);
            }
        }
    }

    /// Sends the slot of `kind` starting at `lost_before`, a slot boundary,
    /// empty, telling the store that the agent skipped everything of the
    /// kind before it, the slots not sent yet becoming a catch-up gap.
    pub(super) fn skip(&mut self, store: &Store, kind: Kind, lost_before: i64) {
        assert_eq!(lost_before.rem_euclid(SLOT), 0, "a slot boundary");
        self.send_slot(store, kind, lost_before, Vec::new(), Some(lost_before));
    }

    fn next(&self, kind: Kind) -> i64 {
        self.next
            .get(&(kind as u8))
            .copied()
            .expect("the cursor read creates a cursor of every kind")
    }

    fn send_slot(
        &mut self,
        store: &Store,
        kind: Kind,
        slot_start: i64,
        observations: Vec<DaiObservation>,
        lost_before: Option<i64>,
    ) {
        let networks = store.customer_networks_map().get(self.customer).unwrap();
        let batch = DaiObservationBatch {
            restore_generation: store.dai_restore_generation().unwrap(),
            config_epoch: store.dai_sensor_config_epoch(&self.sensor).unwrap(),
            network_digest: dai_network_digest(networks.as_ref()).unwrap().digest,
            sensor: self.sensor.clone(),
            kind,
            slot_start,
            slot_len_secs: 300,
            send_id: u64::try_from(slot_start).unwrap() ^ u64::from(kind as u8),
            part: 0,
            part_count: 1,
            observations,
            last_record_time: Some(slot_start + SLOT),
            late_slots: Vec::new(),
            reextract_mark: None,
            lost_before,
            counted_from: slot_start,
        };
        let outcome = store.store_dai_observations(&batch, wall_clock()).unwrap();
        assert!(
            matches!(outcome, DaiStoreOutcome::Stored { .. }),
            "{outcome:?}"
        );
        self.next.insert(kind as u8, slot_start + SLOT);
    }
}

/// Applies every pending observation of every sensor.
pub(super) fn apply_all(store: &Store) {
    while let Some(head) = store.dai_pending_heads().unwrap().into_iter().next() {
        store
            .apply_dai_slot(
                &head.sensor,
                head.slot_start,
                DAI_APPLY_DEFAULT_MAX_COUNT,
                wall_clock(),
            )
            .unwrap();
    }
}

/// Runs `query` as a System Administrator, and returns its data, asserting
/// it has no error.
pub(super) async fn data(schema: &TestSchema, query: &str) -> Value {
    let res = schema.execute_as_system_admin(query).await;
    assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
    res.data.into_json().unwrap()
}

/// Runs `query` as a System Administrator at the request time `now`, and
/// returns its data, asserting it has no error.
pub(super) async fn data_at(schema: &TestSchema, query: &str, now: i64) -> Value {
    let res = schema
        .execute_as_system_admin_with_data(query, RequestTime(now))
        .await;
    assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
    res.data.into_json().unwrap()
}

/// Runs `query` as a System Administrator, and returns its one error.
pub(super) async fn refused(schema: &TestSchema, query: &str) -> async_graphql::ServerError {
    let res = schema.execute_as_system_admin(query).await;
    assert_eq!(res.errors.len(), 1, "{query}: {:?}", res.errors);
    res.errors.into_iter().next().unwrap()
}

/// Returns the `extensions.code` of `error`.
pub(super) fn code(error: &async_graphql::ServerError) -> Option<String> {
    match error.extensions.as_ref()?.get("code")? {
        async_graphql::Value::String(code) => Some(code.clone()),
        _ => None,
    }
}

/// Returns the extension `name` of `error` as JSON.
pub(super) fn extension(error: &async_graphql::ServerError, name: &str) -> Value {
    error
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(name))
        .cloned()
        .unwrap_or(async_graphql::Value::Null)
        .into_json()
        .unwrap()
}

/// Runs `query` as `role` scoped to `customers`.
pub(super) async fn run_as(
    schema: &TestSchema,
    query: &str,
    role: Role,
    customers: &[u32],
) -> async_graphql::Response {
    schema
        .execute_as_scoped_user(query, role, Some(customers.to_vec()))
        .await
}

/// Returns the default site token of `customer`, creating it if needed.
pub(super) fn default_site(store: &Store, customer: u32) -> String {
    store.ensure_default_site(customer).unwrap()
}

/// Closes the store of `schema`, moves every row of the sensor site
/// history `elapsed` nanoseconds earlier, and opens it again, as if that
/// much time had passed since the site changes.
///
/// review-database takes the time of a site change from the clock, and a
/// change takes effect from the next 5-minute boundary, so a test that
/// checks what holds once a change is in effect moves the change instead of
/// waiting. A row's key ends with its effective time, an `i64` written
/// big-endian with its sign bit flipped; its value is left as it is.
pub(super) async fn after(schema: TestSchema, elapsed: i64) -> TestSchema {
    const STATES_DIRECTORY: &str = "states.db";
    const SENSOR_SITES: &str = "dai sensor sites";
    const SIGN_BIT: u64 = 1 << 63;

    let TestSchema {
        dir,
        store,
        schema: graphql,
        ..
    } = schema;
    drop(graphql);
    drop(store);
    {
        // Every column family of an existing database has to be opened with
        // it.
        let path = dir.path().join(STATES_DIRECTORY);
        let options = rocksdb::Options::default();
        let column_families = rocksdb::DB::list_cf(&options, &path).unwrap();
        let db = rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
            &options,
            &path,
            column_families,
        )
        .unwrap();
        let sensor_sites = db.cf_handle(SENSOR_SITES).unwrap();
        let rows: Vec<RawRow> = db
            .iterator_cf(sensor_sites, rocksdb::IteratorMode::Start)
            .map(Result::unwrap)
            .collect();
        for (key, _) in &rows {
            db.delete_cf(sensor_sites, key).unwrap();
        }
        for (key, value) in rows {
            let (prefix, time) = key.split_at(key.len() - 8);
            let time = u64::from_be_bytes(time.try_into().unwrap()) ^ SIGN_BIT;
            let time = i64::from_be_bytes(time.to_be_bytes()) - elapsed;
            let time = u64::from_be_bytes(time.to_be_bytes()) ^ SIGN_BIT;
            let mut moved = prefix.to_vec();
            moved.extend_from_slice(&time.to_be_bytes());
            db.put_cf(sensor_sites, moved, value).unwrap();
        }
    }
    TestSchema::new_in(
        std::sync::Arc::new(crate::graphql::MockAgentManager {}),
        dir,
    )
    .await
}
