use std::sync::{Arc, Mutex};

use async_graphql::{Context, Object, Result, SimpleObject};

use super::{IpAddress, Role, RoleGuard};
const MAX_NUM_IP_LOCATION_LIST: usize = 200;

#[derive(Default)]
pub(super) struct IpLocationQuery;

#[Object]
impl IpLocationQuery {
    /// The location of an IP address.
    #[allow(unused_mut)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ip_location(
        &self,
        ctx: &Context<'_>,
        address: IpAddress,
    ) -> Result<Option<IpLocation>> {
        let addr = address.0;
        let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() else {
            return Err("IP location database unavailable".into());
        };
        let record = {
            if let Ok(locator) = mutex.lock() {
                locator
                    .ip_lookup(addr)
                    .ok()
                    .map(std::convert::TryInto::try_into)
            } else {
                None
            }
        };

        Ok(record.transpose()?)
    }

    /// The list of locations for up to 200 IP addresses.
    #[allow(unused_mut)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ip_location_list(
        &self,
        ctx: &Context<'_>,
        mut addresses: Vec<IpAddress>,
    ) -> Result<Vec<IpLocationItem>> {
        let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() else {
            return Err("IP location database unavailable".into());
        };

        addresses.truncate(MAX_NUM_IP_LOCATION_LIST);
        let locator = mutex
            .lock()
            .map_err(|_| "Failed to lock IP location database")?;
        let records = addresses
            .iter()
            .filter_map(|addr| {
                locator
                    .ip_lookup(addr.0)
                    .ok()
                    .map(std::convert::TryInto::try_into)
                    .and_then(|r| {
                        r.ok().map(|location| IpLocationItem {
                            address: addr.0.to_string(),
                            location,
                        })
                    })
            })
            .collect();

        Ok(records)
    }
}

#[derive(SimpleObject)]
struct IpLocation {
    latitude: Option<f32>,
    longitude: Option<f32>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    zip_code: Option<String>,
    time_zone: Option<String>,
    net_speed: Option<String>,
    idd_code: Option<String>,
    area_code: Option<String>,
    weather_station_code: Option<String>,
    weather_station_name: Option<String>,
    mcc: Option<String>,
    mnc: Option<String>,
    mobile_brand: Option<String>,
    elevation: Option<String>,
    usage_type: Option<String>,
}

#[derive(SimpleObject)]
struct IpLocationItem {
    address: String,
    location: IpLocation,
}

impl TryFrom<ip2location::Record<'_>> for IpLocation {
    type Error = &'static str;
    fn try_from(record: ip2location::Record) -> Result<Self, Self::Error> {
        use ip2location::Record;
        match record {
            Record::LocationDb(record) => Ok(Self {
                latitude: record.latitude,
                longitude: record.longitude,
                country: record.country.map(|c| c.short_name.to_string()),
                region: record.region.map(|r| r.to_string()),
                city: record.city.map(|r| r.to_string()),
                isp: record.isp.map(|r| r.to_string()),
                domain: record.domain.map(|r| r.to_string()),
                zip_code: record.zip_code.map(|r| r.to_string()),
                time_zone: record.time_zone.map(|r| r.to_string()),
                net_speed: record.net_speed.map(|r| r.to_string()),
                idd_code: record.idd_code.map(|r| r.to_string()),
                area_code: record.area_code.map(|r| r.to_string()),
                weather_station_code: record.weather_station_code.map(|r| r.to_string()),
                weather_station_name: record.weather_station_name.map(|r| r.to_string()),
                mcc: record.mcc.map(|r| r.to_string()),
                mnc: record.mnc.map(|r| r.to_string()),
                mobile_brand: record.mobile_brand.map(|r| r.to_string()),
                elevation: record.elevation.map(|r| r.to_string()),
                usage_type: record.usage_type.map(|r| r.to_string()),
            }),
            Record::ProxyDb(_) => Err("Failed to create IpLocation from ProxyDb record"),
        }
    }
}
