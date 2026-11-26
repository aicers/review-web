//! The operator device operations: import, merge, split, state change and
//! service removal.

use std::net::Ipv4Addr;

use async_graphql::{Context, Enum, InputObject, Object, Result, types::ID};
use review_database::{
    DaiActivityChange, DaiIdentifier, DaiImportOutcome, DaiImportRow, DaiImportRowError,
    DaiResolveItem, DaiResolveItemError, DaiResolveWhen, Store,
};

use super::device::DaiIdentifierKind;
use super::{
    DaiActivity, DaiVerdict, dai_refusal, parse_device_id, parse_ip, request_time,
    writable_customer,
};
use crate::graphql::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct DaiOperatorMutation;

#[Object]
impl DaiOperatorMutation {
    /// Imports operator device rows, and returns one result per row, in
    /// input order.
    ///
    /// Rows apply in order, each seeing the earlier ones. A row whose asset
    /// id a device holds replaces that device's name, MACs, fixed IPs and
    /// note with the row's (`UPDATED`); else a row whose MACs belong to one
    /// observed device without an asset id attaches the asset id to it, then
    /// sets the values (`ATTACHED`); else a new device holding the asset id
    /// is created (`CREATED`). A refused row (`ERROR`) writes nothing, and
    /// the other rows are written. A fixed IP without `site` is at the
    /// customer's one site in use; for a multi-site customer it is a row
    /// error. More than 10,000 rows refuse the whole call, and nothing is
    /// written.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn import_dai_devices(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        rows: Vec<DaiImportRowInput>,
    ) -> Result<Vec<DaiImportResult>> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let site_in_use = if rows.len() <= review_database::DAI_IMPORT_MAX_ROWS
            && rows
                .iter()
                .any(|row| row.fixed_ips.iter().any(|ip| ip.site.is_none()))
        {
            site_in_use(&store, customer_id, request_time(ctx)?)?
        } else {
            SiteInUse::None
        };
        let mut rows_at_unstored = Vec::with_capacity(rows.len());
        let (mut rows, parse_errors): (Vec<DaiImportRow>, Vec<Option<ParsedRowError>>) = rows
            .into_iter()
            .map(|row| match row.parse(&site_in_use) {
                Ok((row, at_unstored)) => {
                    rows_at_unstored.push(at_unstored);
                    (row, None)
                }
                Err(error) => {
                    rows_at_unstored.push(Vec::new());
                    (placeholder(&error.asset_id), Some(error))
                }
            })
            .unzip();
        if matches!(site_in_use, SiteInUse::Unstored) {
            place_at_default_site(&store, customer_id, &mut rows, &rows_at_unstored)?;
        }
        let outcomes = store
            .import_dai_devices(customer_id, &rows)
            .map_err(dai_refusal)?;
        if outcomes.len() != parse_errors.len() {
            return Err("review-database answered a different number of rows".into());
        }
        Ok(parse_errors
            .into_iter()
            .zip(outcomes)
            .map(|(parse_error, outcome)| DaiImportResult::new(parse_error, outcome))
            .collect())
    }

    /// Merges the devices `others` into `survivor`, and returns the
    /// survivor's id.
    ///
    /// The survivor takes the others' bindings, identifiers, names,
    /// services, software strings and fixed IPs, the others are removed, and
    /// their ids become aliases of the survivor. Merging devices with
    /// different asset ids, or the survivor into itself, is refused. Old ids
    /// are followed to the current devices.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn merge_dai_devices(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        survivor: ID,
        others: Vec<ID>,
    ) -> Result<ID> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let survivor = parse_device_id(&survivor)?;
        let others = others
            .iter()
            .map(|other| parse_device_id(other))
            .collect::<Result<Vec<_>>>()?;
        let survivor = store
            .merge_dai_devices(customer_id, survivor, &others)
            .map_err(dai_refusal)?;
        Ok(ID(survivor.to_string()))
    }

    /// Moves the identifiers `identifiers` of the device `deviceId`, and the
    /// bindings whose evidence identifier is one of them, to a new device,
    /// and returns the new device's id.
    ///
    /// Choosing no identifier, every identifier of the device, or one it
    /// does not hold, is refused. An old id is followed to the current
    /// device.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn split_dai_device(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        device_id: ID,
        identifiers: Vec<DaiIdentifierInput>,
    ) -> Result<ID> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let device = parse_device_id(&device_id)?;
        let identifiers: Vec<DaiIdentifier> = identifiers
            .into_iter()
            .map(|identifier| DaiIdentifier {
                kind: identifier.kind.into(),
                value: identifier.value,
            })
            .collect();
        let new = store
            .split_dai_device(customer_id, device, &identifiers)
            .map_err(dai_refusal)?;
        Ok(ID(new.to_string()))
    }

    /// Sets the verdict, the activity, or both, of each of up to 1,000
    /// devices, and returns `true`.
    ///
    /// At least one of `verdict` and `activity` is given, and `NOT_SEEN`,
    /// which only retention sets, is not accepted. Each device whose state
    /// changes gets one change history entry; bindings and resolve answers
    /// do not change. An unknown id refuses the whole call. Old ids are
    /// followed to the current devices.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn set_dai_device_states(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        device_ids: Vec<ID>,
        verdict: Option<DaiVerdict>,
        activity: Option<DaiActivity>,
    ) -> Result<bool> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        if verdict.is_none() && activity.is_none() {
            return Err("give at least one of verdict and activity".into());
        }
        let activity = match activity {
            None => None,
            Some(DaiActivity::Active) => Some(DaiActivityChange::Active),
            Some(DaiActivity::Hidden) => Some(DaiActivityChange::Hidden),
            Some(DaiActivity::NotSeen) => {
                return Err("activity NOT_SEEN is set by retention only".into());
            }
        };
        let devices = device_ids
            .iter()
            .map(|device| parse_device_id(device))
            .collect::<Result<Vec<_>>>()?;
        store
            .set_dai_device_states(customer_id, &devices, verdict.map(Into::into), activity)
            .map_err(dai_refusal)?;
        Ok(true)
    }

    /// Marks the service of the device `deviceId` on `port` of the IP
    /// protocol number `protocol` as removed by an operator, and returns
    /// `true`.
    ///
    /// The service stays in the device's detail with the removed flag, and
    /// the device's version does not change. An old id is followed to the
    /// current device.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_dai_service(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        device_id: ID,
        port: u16,
        protocol: u8,
    ) -> Result<bool> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let device = parse_device_id(&device_id)?;
        store
            .remove_dai_service(customer_id, device, port, protocol)
            .map_err(dai_refusal)?;
        Ok(true)
    }
}

/// The token a parsed row carries for the customer's default site while that
/// site is not stored.
///
/// No site has it, as a token is 8 characters of `[a-z0-9]`. It sorts after
/// every such token, and review-database checks a row's sites in their order,
/// so a row also naming another unknown token is refused naming that one.
const UNSTORED_SITE: &str = "\u{10FFFF}";

/// The site a fixed IP without a site token is at.
enum SiteInUse {
    /// The customer's one site in use.
    One(String),
    /// The customer's one site in use is its default site, which is not
    /// stored yet.
    Unstored,
    /// The customer is multi-site, so a fixed IP needs a site token.
    MultiSite,
    /// No row needs it.
    None,
}

/// Returns the customer's one site in use, writing nothing.
///
/// The site is the one review-database resolves an item without a site
/// token at: the site holding the customer's sensors, or the default site
/// if none does. A multi-site customer, whose sensors fall in two or more
/// sites, has none.
fn site_in_use(store: &Store, customer_id: u32, now: i64) -> Result<SiteInUse> {
    let probe = DaiResolveItem {
        site: None,
        ip: Ipv4Addr::UNSPECIFIED.into(),
        when: DaiResolveWhen::At(now),
    };
    let answer = store
        .dai_resolve(customer_id, std::slice::from_ref(&probe), false, now)
        .map_err(dai_refusal)?
        .into_iter()
        .next()
        .ok_or("review-database answered no item")?;
    match answer {
        Ok(answer) => Ok(SiteInUse::One(answer.site)),
        Err(DaiResolveItemError::SiteRequired) => Ok(SiteInUse::MultiSite),
        Err(DaiResolveItemError::NoSite) => Ok(SiteInUse::Unstored),
        Err(error) => Err(error.to_string().into()),
    }
}

/// Stores the customer's default site and puts its token in the fixed IPs
/// `at_unstored` gives for each row, if review-database's checks of one of
/// those rows reach its fixed IPs' sites; otherwise leaves the rows as they
/// are, for review-database to refuse.
///
/// A row whose site-less fixed IPs are at the unstored default site needs
/// that site stored before it can be written, but storing it for a row that
/// is then refused would write for an error row. So the rows are first
/// probed in one import that writes nothing: each row with such a fixed IP
/// as it is, and every other row as its placeholder, so each probed row sees
/// the asset ids of the rows before it as the import will. review-database
/// checks a row's asset id and MACs first and its fixed IPs' sites next,
/// before it writes anything, and no site has the unstored token, so a
/// probed row it refuses for an unknown site passed every check before the
/// sites. The row also has to name no other unknown site, which the stored
/// sites tell, since review-database names only the first. The rest of review-database's checks need the sites stored, so a
/// row refused by one of them (its MACs and asset id naming other devices,
/// or a fixed IP held by another device) still leaves the default site
/// stored.
fn place_at_default_site(
    store: &Store,
    customer_id: u32,
    rows: &mut [DaiImportRow],
    at_unstored: &[Vec<usize>],
) -> Result<()> {
    if at_unstored.iter().all(Vec::is_empty) {
        return Ok(());
    }
    let probe: Vec<DaiImportRow> = rows
        .iter()
        .zip(at_unstored)
        .map(|(row, at)| {
            if at.is_empty() {
                placeholder(&row.asset_id)
            } else {
                row.clone()
            }
        })
        .collect();
    let outcomes = store
        .import_dai_devices(customer_id, &probe)
        .map_err(dai_refusal)?;
    let stored: Vec<String> = store
        .dai_sites(customer_id)
        .map_err(dai_refusal)?
        .into_iter()
        .map(|site| site.token)
        .collect();
    let reaches_sites = rows
        .iter()
        .zip(at_unstored)
        .zip(&outcomes)
        .any(|((row, at), outcome)| {
            !at.is_empty()
                && matches!(
                    outcome,
                    DaiImportOutcome::Error(DaiImportRowError::UnknownSite { .. })
                )
                && row
                    .fixed_ips
                    .iter()
                    .all(|(site, _)| site == UNSTORED_SITE || stored.contains(site))
        });
    if !reaches_sites {
        return Ok(());
    }
    let token = store
        .ensure_default_site(customer_id)
        .map_err(dai_refusal)?;
    for (row, at) in rows.iter_mut().zip(at_unstored) {
        for &index in at {
            if let Some((site, _)) = row.fixed_ips.get_mut(index) {
                site.clone_from(&token);
            }
        }
    }
    Ok(())
}

/// Returns the row review-database is given in place of a row this layer
/// refused or does not probe: one it is sure to refuse, for an empty or
/// repeated asset id or else for its MAC, writing nothing, and that still
/// takes the row's place in the request, so a later row repeating its asset
/// id is refused as such.
fn placeholder(asset_id: &str) -> DaiImportRow {
    DaiImportRow {
        asset_id: asset_id.to_string(),
        macs: vec![Vec::new()],
        ..DaiImportRow::default()
    }
}

/// A row of an operator device import.
#[derive(InputObject)]
struct DaiImportRowInput {
    /// The operator asset id; required, and unique within the customer.
    asset_id: String,
    /// The operator name; null or empty for none.
    name: Option<String>,
    /// The MAC addresses, as `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff` or
    /// `aabb.ccdd.eeff`, in any case.
    macs: Vec<String>,
    /// The fixed IPs.
    fixed_ips: Vec<DaiFixedIpInput>,
    /// The note; null or empty for none.
    note: Option<String>,
}

impl DaiImportRowInput {
    /// Returns the row review-database takes, with the positions of its
    /// fixed IPs at the unstored default site, or the row's parse error.
    fn parse(self, site_in_use: &SiteInUse) -> Result<(DaiImportRow, Vec<usize>), ParsedRowError> {
        let refuse = |reason, message| ParsedRowError {
            asset_id: self.asset_id.clone(),
            reason,
            message,
        };
        let mut macs = Vec::with_capacity(self.macs.len());
        for mac in &self.macs {
            macs.push(parse_mac(mac).ok_or_else(|| {
                refuse(
                    DaiImportErrorReason::InvalidMac,
                    format!("{mac:?} is not a MAC address"),
                )
            })?);
        }
        let mut fixed_ips = Vec::with_capacity(self.fixed_ips.len());
        let mut at_unstored = Vec::new();
        for fixed in &self.fixed_ips {
            let ip = parse_ip(&fixed.ip, "fixed IP")
                .map_err(|message| refuse(DaiImportErrorReason::InvalidIp, message))?;
            let site = match (&fixed.site, site_in_use) {
                (Some(site), _) | (None, SiteInUse::One(site)) => site.clone(),
                (None, SiteInUse::Unstored) => {
                    at_unstored.push(fixed_ips.len());
                    UNSTORED_SITE.to_string()
                }
                (None, _) => {
                    return Err(refuse(
                        DaiImportErrorReason::SiteRequired,
                        format!("the customer is multi-site, so fixed IP {ip} needs a site token"),
                    ));
                }
            };
            fixed_ips.push((site, ip));
        }
        let row = DaiImportRow {
            asset_id: self.asset_id,
            name: self.name,
            macs,
            fixed_ips,
            memo: self.note,
        };
        Ok((row, at_unstored))
    }
}

/// Returns the 6 bytes of `text`, a MAC address as `aa:bb:cc:dd:ee:ff`,
/// `aa-bb-cc-dd-ee-ff` or `aabb.ccdd.eeff`, in any case.
fn parse_mac(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let groups: Vec<&str> = if text.contains(':') {
        text.split(':').collect()
    } else if text.contains('-') {
        text.split('-').collect()
    } else {
        text.split('.').collect()
    };
    let group_len = match groups.len() {
        6 => 2,
        3 => 4,
        _ => return None,
    };
    if text.contains('.') != (group_len == 4) {
        return None;
    }
    let mut bytes = Vec::with_capacity(6);
    for group in groups {
        if group.len() != group_len || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        for pair in group.as_bytes().chunks(2) {
            let pair = std::str::from_utf8(pair).ok()?;
            bytes.push(u8::from_str_radix(pair, 16).ok()?);
        }
    }
    Some(bytes)
}

/// A fixed IP of an import row.
#[derive(InputObject)]
struct DaiFixedIpInput {
    /// The site token; null for the customer's one site in use, which a
    /// multi-site customer does not have.
    site: Option<String>,
    /// The IP address.
    ip: String,
}

/// A strong identifier of a device to move.
#[derive(InputObject)]
struct DaiIdentifierInput {
    kind: DaiIdentifierKind,
    /// The value, in the form `daiDevice` lists it.
    value: String,
}

/// A row this layer could not parse.
struct ParsedRowError {
    asset_id: String,
    reason: DaiImportErrorReason,
    message: String,
}

/// The outcome of one import row.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(name = "DaiImportOutcome")]
enum DaiImportOutcomeKind {
    /// A new device was created for the row.
    Created,
    /// The device holding the row's asset id was updated, or was already as
    /// the row says.
    Updated,
    /// The row's asset id was attached to the device holding its MACs.
    Attached,
    /// The row was refused and wrote nothing.
    Error,
}

/// Why an import row was refused.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
enum DaiImportErrorReason {
    /// The asset id is empty.
    EmptyAssetId,
    /// An earlier row of the request has the asset id.
    DuplicateAssetId,
    /// A MAC does not parse, or is all `00`, all `FF` or a group address.
    InvalidMac,
    /// A fixed IP does not parse.
    InvalidIp,
    /// A fixed IP names a token that is not one of the customer's sites.
    UnknownSite,
    /// A fixed IP has no site token and the customer is multi-site.
    SiteRequired,
    /// The row's asset id and MACs name two or more devices; merge them
    /// first.
    MergeFirst,
    /// The row's asset id is new, but its MACs belong to a device with
    /// another asset id.
    AssetIdMismatch,
    /// A fixed IP of the row is fixed to another device.
    FixedIpHeld,
}

/// The refusal of one import row.
struct DaiImportError {
    reason: DaiImportErrorReason,
    message: String,
    device_ids: Vec<ID>,
}

#[Object]
impl DaiImportError {
    async fn reason(&self) -> DaiImportErrorReason {
        self.reason
    }

    /// The cause, in words.
    async fn message(&self) -> &str {
        &self.message
    }

    /// The devices the refusal names: the devices to merge first, the device
    /// holding the row's MACs with another asset id, or the device a fixed
    /// IP is fixed to.
    async fn device_ids(&self) -> &[ID] {
        &self.device_ids
    }
}

impl From<DaiImportRowError> for DaiImportError {
    fn from(error: DaiImportRowError) -> Self {
        let message = error.to_string();
        let (reason, device_ids) = match error {
            DaiImportRowError::EmptyAssetId => (DaiImportErrorReason::EmptyAssetId, Vec::new()),
            DaiImportRowError::DuplicateAssetId { .. } => {
                (DaiImportErrorReason::DuplicateAssetId, Vec::new())
            }
            DaiImportRowError::InvalidMac { .. } => (DaiImportErrorReason::InvalidMac, Vec::new()),
            DaiImportRowError::UnknownSite { .. } => {
                (DaiImportErrorReason::UnknownSite, Vec::new())
            }
            DaiImportRowError::MergeFirst { devices } => (
                DaiImportErrorReason::MergeFirst,
                devices
                    .iter()
                    .map(|device| ID(device.to_string()))
                    .collect(),
            ),
            DaiImportRowError::FixedIpHeld { device, .. } => (
                DaiImportErrorReason::FixedIpHeld,
                vec![ID(device.to_string())],
            ),
            DaiImportRowError::AssetIdMismatch { device, .. } => (
                DaiImportErrorReason::AssetIdMismatch,
                vec![ID(device.to_string())],
            ),
        };
        Self {
            reason,
            message,
            device_ids,
        }
    }
}

/// The result of one import row.
struct DaiImportResult {
    outcome: DaiImportOutcomeKind,
    device_id: Option<ID>,
    error: Option<DaiImportError>,
}

impl DaiImportResult {
    /// Returns the result of a row from review-database's `outcome`, the
    /// row's own parse error taking the place of the refusal of its
    /// placeholder.
    fn new(parse_error: Option<ParsedRowError>, outcome: DaiImportOutcome) -> Self {
        let device = |outcome, device: String| Self {
            outcome,
            device_id: Some(ID(device)),
            error: None,
        };
        match outcome {
            DaiImportOutcome::Created { device: id } => {
                device(DaiImportOutcomeKind::Created, id.to_string())
            }
            DaiImportOutcome::Updated { device: id } => {
                device(DaiImportOutcomeKind::Updated, id.to_string())
            }
            DaiImportOutcome::Attached { device: id } => {
                device(DaiImportOutcomeKind::Attached, id.to_string())
            }
            DaiImportOutcome::Error(error) => {
                let error = match (parse_error, error) {
                    (Some(parsed), DaiImportRowError::InvalidMac { .. }) => DaiImportError {
                        reason: parsed.reason,
                        message: parsed.message,
                        device_ids: Vec::new(),
                    },
                    (_, error) => error.into(),
                };
                Self {
                    outcome: DaiImportOutcomeKind::Error,
                    device_id: None,
                    error: Some(error),
                }
            }
        }
    }
}

#[Object]
impl DaiImportResult {
    async fn outcome(&self) -> DaiImportOutcomeKind {
        self.outcome
    }

    /// The device the row created, updated or attached to; null for an
    /// error.
    async fn device_id(&self) -> Option<&ID> {
        self.device_id.as_ref()
    }

    /// Why the row was refused; null unless the outcome is `ERROR`.
    async fn error(&self) -> Option<&DaiImportError> {
        self.error.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_mac;

    #[test]
    fn a_mac_parses_in_each_accepted_form_and_case() {
        let mac = Some(vec![0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff]);
        for text in [
            "aa:bb:cc:0d:ee:ff",
            "AA:BB:CC:0D:EE:FF",
            "aa-bb-cc-0d-ee-ff",
            "Aa-Bb-cC-0d-eE-Ff",
            "aabb.cc0d.eeff",
            "AABB.CC0D.EEFF",
        ] {
            assert_eq!(parse_mac(text), mac, "{text}");
        }
    }

    #[test]
    fn a_mac_in_another_form_does_not_parse() {
        for text in [
            "",
            "aabbcc0deeff",
            "aa:bb:cc:0d:ee",
            "aa:bb:cc:0d:ee:ff:00",
            "aa:bb-cc:0d:ee:ff",
            "aa:bb:cc:0d:ee:fg",
            "a:bb:cc:0d:ee:fff",
            "aabb.cc0d.eef",
            "aa.bb.cc.0d.ee.ff",
            "aab.bcc0d.eeff",
            "+a:bb:cc:0d:ee:ff",
        ] {
            assert_eq!(parse_mac(text), None, "{text}");
        }
    }
}
