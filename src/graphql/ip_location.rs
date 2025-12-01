use std::net::IpAddr;

use async_graphql::{Context, Object, Result, SimpleObject};

use super::{IpAddress, Role, RoleGuard};
const MAX_NUM_IP_LOCATION_LIST: usize = 200;

#[cfg(test)]
use self::tests::TestIpLocator;

#[derive(Copy, Clone)]
enum IpLocatorSource<'a> {
    #[cfg(test)]
    Mock(&'a TestIpLocator),
    Db(&'a ip2location::DB),
}

impl<'a> IpLocatorSource<'a> {
    fn lookup(self, addr: IpAddr) -> Option<ip2location::Record<'a>> {
        match self {
            #[cfg(test)]
            Self::Mock(locator) => Some(locator.ip_lookup(addr)),
            Self::Db(locator) => locator.ip_lookup(addr).ok(),
        }
    }
}

fn get_locator<'ctx>(ctx: &'ctx Context<'ctx>) -> Result<IpLocatorSource<'ctx>> {
    #[cfg(test)]
    if let Ok(locator) = ctx.data::<TestIpLocator>() {
        return Ok(IpLocatorSource::Mock(locator));
    }

    let locator = ctx
        .data::<ip2location::DB>()
        .map_err(|_| "IP location database unavailable")?;
    Ok(IpLocatorSource::Db(locator))
}

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
        let locator = get_locator(ctx)?;
        let record = locator.lookup(addr).map(std::convert::TryInto::try_into);

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
        let locator = get_locator(ctx)?;

        addresses.truncate(MAX_NUM_IP_LOCATION_LIST);
        let records = addresses
            .iter()
            .filter_map(|addr| {
                locator
                    .lookup(addr.0)
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
            Record::LocationDb(record) => {
                // ip2location returns (0.0, 0.0) for private/unresolved IPs; treat as no location.
                let (latitude, longitude) = match (record.latitude, record.longitude) {
                    (Some(lat), Some(lon)) if lat == 0.0 && lon == 0.0 => (None, None),
                    (lat, lon) => (lat, lon),
                };
                Ok(Self {
                    latitude,
                    longitude,
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
                })
            }
            Record::ProxyDb(_) => Err("Failed to create IpLocation from ProxyDb record"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::TestSchema;

    #[derive(Clone)]
    pub(super) struct TestIpLocator {
        latitude: Option<f32>,
        longitude: Option<f32>,
    }

    impl TestIpLocator {
        fn new(latitude: Option<f32>, longitude: Option<f32>) -> Self {
            Self {
                latitude,
                longitude,
            }
        }

        pub(super) fn ip_lookup(&self, addr: IpAddr) -> ip2location::Record<'static> {
            ip2location::Record::LocationDb(Box::new(ip2location::LocationRecord {
                ip: addr,
                latitude: self.latitude,
                longitude: self.longitude,
                ..Default::default()
            }))
        }
    }

    #[tokio::test]
    async fn ip_location_returns_null_for_zero_coordinates() {
        let schema = TestSchema::new().await;
        let locator = TestIpLocator::new(Some(0.0), Some(0.0));

        let res = schema
            .execute_with_data(
                r#"
                {
                    ipLocation(address: "127.0.0.1") {
                        latitude
                        longitude
                    }
                }
                "#,
                locator,
            )
            .await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            "{ipLocation: {latitude: null, longitude: null}}"
        );
    }

    #[tokio::test]
    async fn ip_location_list_clears_zero_coordinates() {
        let schema = TestSchema::new().await;
        let locator = TestIpLocator::new(Some(0.0), Some(0.0));

        let res = schema
            .execute_with_data(
                r#"
                {
                    ipLocationList(addresses: ["127.0.0.1", "192.0.2.1"]) {
                        address
                        location {
                            latitude
                            longitude
                        }
                    }
                }
                "#,
                locator,
            )
            .await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            "{ipLocationList: [{address: \"127.0.0.1\", location: {latitude: null, longitude: null}}, {address: \"192.0.2.1\", location: {latitude: null, longitude: null}}]}"
        );
    }
}
