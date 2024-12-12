use std::{
    collections::HashMap,
    num::NonZeroU8,
    sync::{Arc, Mutex},
};

use async_graphql::{Context, Object, OutputType, Result, SimpleObject};
use database::{IndexedTable, Iterable};
use num_traits::ToPrimitive;
use review_database::{self as database, Direction, Event, EventFilter};
use tracing::warn;

use super::{from_filter_input, EventListFilterInput};
use crate::graphql::{Role, RoleGuard};

#[derive(Default)]
pub(in crate::graphql) struct EventGroupQuery;

#[Object]
impl EventGroupQuery {
    /// The number of events for each category, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_category(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<u8>> {
        let (values, counts) = count_events(ctx, &filter, Event::count_category, first).await?;
        let values = values.into_iter().filter_map(|v| v.to_u8()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each country, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_country(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(ctx, &filter, Event::count_country, first).await?;
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each IP address, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(ctx, &filter, Event::count_ip_address, first).await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each source and destination IP address pair,
    /// with timestamp on or after `start` and before `end`. Each entry in
    /// `values` is a string representation of the source and destination IP
    /// address pair. For example, source IP address 10.0.0.1 and destination IP
    /// address 10.0.0.2 become "10.0.0.1-10.0.0.2".
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address_pair(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, Event::count_ip_address_pair, first).await?;
        let values = values
            .into_iter()
            .map(|(src, dst)| {
                let mut value = src.to_string();
                value.push('-');
                value.push_str(&dst.to_string());
                value
            })
            .collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each source and destination IP address pair and
    /// event kind, with timestamp on or after `start` and before `end`. Each
    /// entry in `values` is a string representation of the source and
    /// destination IP address pair and kind. For example, a DNS covert channel
    /// event with source IP address 10.0.0.1, destination IP address 10.0.0.2
    /// become "10.0.0.1-10.0.0.2-DNS Covert Channel".
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address_pair_and_kind(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, Event::count_ip_address_pair_and_kind, first).await?;
        let values = values
            .into_iter()
            .map(|(src, dst, kind)| {
                let mut value = src.to_string();
                value.push('-');
                value.push_str(&dst.to_string());
                value.push('-');
                value.push_str(kind);
                value
            })
            .collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each source IP address, with timestamp on or
    /// after `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_source_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, Event::count_src_ip_address, first).await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each destination IP address, with timestamp on
    /// or after `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_destination_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, Event::count_dst_ip_address, first).await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each kind, with timestamp on or after `start`
    /// and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_kind(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(ctx, &filter, Event::count_kind, first).await?;
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each level, with timestamp on or after `start`
    /// and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_level(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<u8>> {
        let (values, counts) = count_events(ctx, &filter, Event::count_level, first).await?;
        let values = values.into_iter().map(NonZeroU8::get).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each network, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_network(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events_by_network(ctx, &filter, first).await?;
        Ok(EventCounts { values, counts })
    }

    /// A time series of event frequencies. The period length is given in
    /// seconds.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_frequency_series(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] period: i64,
    ) -> Result<Vec<usize>> {
        let store = crate::graphql::get_store(ctx).await?;

        let start = filter
            .start
            .map(|t| i128::from(t.timestamp_nanos_opt().unwrap_or_default()) << 64)
            .unwrap_or_default();
        let end = filter.end.map_or(i128::MAX, |t| {
            let end = t
                .timestamp_nanos_opt()
                .map_or(i128::MAX, |t| i128::from(t) << 64);
            if end > 0 {
                end - 1
            } else {
                0
            }
        });
        let filter = from_filter_input(&store, &filter)?;
        let db = store.events();
        let locator = if filter.has_country() {
            if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
                Some(Arc::clone(mutex))
            } else {
                return Err("IP location database unavailable".into());
            }
        } else {
            None
        };

        let period = i128::from(period * 1_000_000_000) << 64;
        let mut series = Vec::new();
        let mut cur_end = start + period - 1;
        let mut freq = 0;
        for item in db.iter_from(start, Direction::Forward) {
            let (key, event) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    warn!("invalid event: {:?}", e);
                    continue;
                }
            };
            while key > cur_end || key > end {
                if key > end {
                    break;
                }
                series.push(freq);
                freq = 0;
                cur_end += period;
            }
            if event.matches(locator.clone(), &filter)?.0 {
                freq += 1;
            }
        }
        series.push(freq);
        let Ok(len) = usize::try_from((end - start + period) / period) else {
            return Err("period too short".into());
        };
        series.resize(len, 0);
        Ok(series)
    }
}

#[derive(SimpleObject)]
#[graphql(concrete(name = "StringEventCounter", params(String)))]
#[graphql(concrete(name = "U8EventCounter", params(u8)))]
struct EventCounts<T: OutputType> {
    values: Vec<T>,
    counts: Vec<usize>,
}

type EventCountFn<T> = fn(
    &Event,
    &mut HashMap<T, usize>,
    Option<Arc<Mutex<ip2location::DB>>>,
    &EventFilter,
) -> anyhow::Result<()>;

async fn count_events<T>(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    count: EventCountFn<T>,
    first: i32,
) -> Result<(Vec<T>, Vec<usize>)> {
    let store = crate::graphql::get_store(ctx).await?;

    let start = filter
        .start
        .map(|t| i128::from(t.timestamp_nanos_opt().unwrap_or_default()) << 64)
        .unwrap_or_default();
    let end = filter.end.map_or(i128::MAX, |t| {
        let end = t
            .timestamp_nanos_opt()
            .map_or(i128::MAX, |t| i128::from(t) << 64);
        if end > 0 {
            end - 1
        } else {
            0
        }
    });
    let filter = from_filter_input(&store, filter)?;
    let db = store.events();
    let locator = if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
        Some(Arc::clone(mutex))
    } else {
        None
    };

    let mut counter = HashMap::new();
    for item in db.iter_from(start, Direction::Forward) {
        let (key, event) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn!("invalid event: {:?}", e);
                continue;
            }
        };
        if key > end {
            break;
        }
        count(&event, &mut counter, locator.clone(), &filter)?;
    }

    let mut counter = counter.into_iter().collect::<Vec<_>>();
    counter.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    counter.truncate(usize::try_from(first).unwrap_or(counter.len()));
    let (values, counts) = counter.into_iter().fold(
        (Vec::new(), Vec::new()),
        |(mut values, mut counts), (k, v)| {
            values.push(k);
            counts.push(v);
            (values, counts)
        },
    );
    Ok((values, counts))
}

async fn count_events_by_network(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    first: i32,
) -> Result<(Vec<String>, Vec<usize>)> {
    let store = crate::graphql::get_store(ctx).await?;
    let network_map = store.network_map();
    let networks = load_networks(&network_map)?;

    let start = filter
        .start
        .map(|t| i128::from(t.timestamp_nanos_opt().unwrap_or_default()) << 64)
        .unwrap_or_default();
    let end = filter.end.map_or(i128::MAX, |t| {
        let end = t
            .timestamp_nanos_opt()
            .map_or(i128::MAX, |t| i128::from(t) << 64);
        if end > 0 {
            end - 1
        } else {
            0
        }
    });
    let filter = from_filter_input(&store, filter)?;
    let db = store.events();
    let locator = if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
        Some(Arc::clone(mutex))
    } else {
        None
    };

    let mut counter = HashMap::new();
    for item in db.iter_from(start, Direction::Forward) {
        let (key, event) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn!("invalid event: {:?}", e);
                continue;
            }
        };
        if key > end {
            break;
        }
        event.count_network(&mut counter, &networks, locator.clone(), &filter)?;
    }

    let mut counter = counter.into_iter().collect::<Vec<_>>();
    counter.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    counter.truncate(usize::try_from(first).unwrap_or(counter.len()));
    let (values, counts) = counter.into_iter().fold(
        (Vec::new(), Vec::new()),
        |(mut values, mut counts), (k, v)| {
            values.push(k.to_string());
            counts.push(v);
            (values, counts)
        },
    );
    Ok((values, counts))
}

fn load_networks(
    map: &IndexedTable<review_database::Network>,
) -> anyhow::Result<Vec<review_database::Network>> {
    let mut networks = Vec::new();
    for entry in map.iter(Direction::Forward, None) {
        let network = entry?;
        networks.push(network);
    }
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::{DateTime, NaiveDate, Utc};
    use review_database::{event::DnsEventFields, EventCategory, EventKind, EventMessage};

    use crate::graphql::TestSchema;

    /// Creates an event message at `timestamp` with the given source and
    /// destination `IPv4` addresses.
    fn event_message_at(timestamp: DateTime<Utc>, src: u32, dst: u32) -> EventMessage {
        let fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            session_end_time: timestamp,
            src_addr: Ipv4Addr::from(src).into(),
            src_port: 10000,
            dst_addr: Ipv4Addr::from(dst).into(),
            dst_port: 53,
            proto: 17,
            query: "domain".into(),
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
            confidence: 0.8,
            category: EventCategory::CommandAndControl,
        };
        EventMessage {
            time: timestamp,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn count_events_by_network() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let ts1 = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = NaiveDate::from_ymd_opt(2018, 1, 27)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = NaiveDate::from_ymd_opt(2018, 1, 28)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(
                        name: "n0",
                        description: "",
                        networks: {
                            hosts: ["0.0.0.4"],
                            networks: [],
                            ranges: []
                        },
                        customerIds: [],
                        tagIds: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
        let query = format!(
            "{{ \
                eventCountsByNetwork(
                    filter: {{ start:\"{}\", end:\"{}\" }},
                    first: 10
                ) {{
                    values
                    counts
                }}
            }}",
            ts1, ts3
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventCountsByNetwork: {values: ["0"], counts: [1]}}"#
        );
    }
}
