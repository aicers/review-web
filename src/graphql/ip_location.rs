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
        let Ok(locator) = ctx.data::<ip2location::DB>() else {
            return Err("IP location database unavailable".into());
        };
        let record = locator
            .ip_lookup(addr)
            .ok()
            .map(std::convert::TryInto::try_into);

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
        let Ok(locator) = ctx.data::<ip2location::DB>() else {
            return Err("IP location database unavailable".into());
        };

        addresses.truncate(MAX_NUM_IP_LOCATION_LIST);
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
    use std::net::IpAddr;

    use ip2location::{LocationRecord, Record};

    use super::*;

    fn create_location_record(lat: Option<f32>, lon: Option<f32>) -> Record<'static> {
        let record = LocationRecord {
            ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            latitude: lat,
            longitude: lon,
            ..Default::default()
        };
        Record::LocationDb(Box::new(record))
    }

    #[test]
    fn try_from_zero_coords_returns_none() {
        // When ip2location returns (0.0, 0.0), both latitude and longitude should be None.
        let record = create_location_record(Some(0.0), Some(0.0));
        let location: IpLocation = record.try_into().unwrap();

        assert!(location.latitude.is_none());
        assert!(location.longitude.is_none());
    }

    #[test]
    fn try_from_valid_coords_preserved() {
        // Valid coordinates should be preserved as-is.
        let record = create_location_record(Some(37.7749), Some(-122.4194));
        let location: IpLocation = record.try_into().unwrap();

        assert_eq!(location.latitude, Some(37.7749));
        assert_eq!(location.longitude, Some(-122.4194));
    }

    #[test]
    fn try_from_none_coords_preserved() {
        // When latitude and/or longitude are already None, they remain None.
        let record = create_location_record(None, None);
        let location: IpLocation = record.try_into().unwrap();

        assert!(location.latitude.is_none());
        assert!(location.longitude.is_none());
    }

    #[test]
    fn try_from_partial_none_preserved() {
        // When only one coordinate is None, preserve both as-is (not treated as zero coords).
        let record = create_location_record(Some(37.7749), None);
        let location: IpLocation = record.try_into().unwrap();

        assert_eq!(location.latitude, Some(37.7749));
        assert!(location.longitude.is_none());

        let record = create_location_record(None, Some(-122.4194));
        let location: IpLocation = record.try_into().unwrap();

        assert!(location.latitude.is_none());
        assert_eq!(location.longitude, Some(-122.4194));
    }

    #[test]
    fn try_from_single_zero_coord_preserved() {
        // When only one coordinate is 0.0 (but not both), preserve both.
        // This handles edge cases where a location might legitimately have a zero value.
        let record = create_location_record(Some(0.0), Some(-122.4194));
        let location: IpLocation = record.try_into().unwrap();

        assert_eq!(location.latitude, Some(0.0));
        assert_eq!(location.longitude, Some(-122.4194));

        let record = create_location_record(Some(37.7749), Some(0.0));
        let location: IpLocation = record.try_into().unwrap();

        assert_eq!(location.latitude, Some(37.7749));
        assert_eq!(location.longitude, Some(0.0));
    }

    #[test]
    fn try_from_proxy_db_fails() {
        let proxy_record = ip2location::ProxyRecord::default();
        let record = Record::ProxyDb(Box::new(proxy_record));
        let result: Result<IpLocation, _> = record.try_into();

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Failed to create IpLocation from ProxyDb record"
        );
    }
}
