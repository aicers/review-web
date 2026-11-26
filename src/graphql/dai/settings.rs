//! The device identification settings of each customer.

use async_graphql::{Context, InputObject, Object, Result, StringNumber, types::ID};
use review_database::{DaiSettings, DaiSettingsUpdate};

use super::{accessible_customer, dai_refusal, timestamp, writable_customer};
use crate::graphql::{Role, RoleGuard, timestamp::Timestamp};

#[derive(Default)]
pub(super) struct DaiSettingsQuery;

#[Object]
impl DaiSettingsQuery {
    /// The device identification settings of each customer of
    /// `customerIds`, one entry per id, in order.
    ///
    /// A customer whose settings were never written reads as disabled, never
    /// enabled, an inactivity multiplier of 2, 24 hours without a lease, 180
    /// days of evidence aging, no realm and both revisions 0. One id the
    /// caller is not a member of refuses the whole call with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_customer_settings(
        &self,
        ctx: &Context<'_>,
        customer_ids: Vec<ID>,
    ) -> Result<Vec<DaiCustomerSettings>> {
        let customer_ids = customer_ids
            .iter()
            .map(|customer_id| accessible_customer(ctx, customer_id))
            .collect::<Result<Vec<_>>>()?;
        let store = crate::graphql::get_store(ctx)?;
        customer_ids
            .into_iter()
            .map(|customer_id| {
                let inner = store.dai_settings(customer_id).map_err(dai_refusal)?;
                Ok(DaiCustomerSettings { customer_id, inner })
            })
            .collect()
    }
}

#[derive(Default)]
pub(super) struct DaiSettingsMutation;

#[Object]
impl DaiSettingsMutation {
    /// Replaces every settable device identification setting of the customer
    /// with `input`, given the stored settings `revision`, and returns the
    /// stored settings with the new revision.
    ///
    /// The customer is left with a stored default site. Turning
    /// `deviceAccountIdentification` on records the time of the write as the
    /// last-enabled time; turning it off keeps it. A multiplier or a time of
    /// 0, or an empty realm name, is refused. A `revision` other than the
    /// stored one is refused with the error code `STALE_REVISION`, whose
    /// `storedRevision` extension holds the stored revision.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_dai_customer_settings(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        input: DaiCustomerSettingsInput,
    ) -> Result<DaiCustomerSettings> {
        let (customer_id, _lock, store) = writable_customer(ctx, &customer_id).await?;
        let update = DaiSettingsUpdate {
            device_account_identification: input.device_account_identification,
            inactivity_multiplier: input.inactivity_multiplier,
            no_lease_inactivity_secs: input.no_lease_inactivity_secs.0,
            evidence_aging_secs: input.evidence_aging_secs.0,
            kerberos_preauth_realms: input.kerberos_preauth_realms,
        };
        let inner = store
            .set_dai_settings(customer_id, revision.0, &update)
            .map_err(dai_refusal)?;
        Ok(DaiCustomerSettings { customer_id, inner })
    }
}

/// The device identification settings of a customer.
struct DaiCustomerSettings {
    customer_id: u32,
    inner: DaiSettings,
}

#[Object]
impl DaiCustomerSettings {
    /// The ID of the customer.
    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }

    /// Whether device account identification is enabled.
    async fn device_account_identification(&self) -> bool {
        self.inner.device_account_identification
    }

    /// When device account identification was last turned on; null if it
    /// never was.
    async fn last_enabled_time(&self) -> Option<Timestamp> {
        self.inner.last_enabled_time.map(timestamp)
    }

    /// The multiple of a lease time after which a device with a lease is
    /// inactive.
    async fn inactivity_multiplier(&self) -> u32 {
        self.inner.inactivity_multiplier
    }

    /// The time, in seconds, after which a device without a lease is
    /// inactive.
    async fn no_lease_inactivity_secs(&self) -> StringNumber<u64> {
        StringNumber(self.inner.no_lease_inactivity_secs)
    }

    /// The time, in seconds, after which evidence ages out.
    async fn evidence_aging_secs(&self) -> StringNumber<u64> {
        StringNumber(self.inner.evidence_aging_secs)
    }

    /// The Kerberos realms confirmed to enforce pre-authentication, in the
    /// order given.
    async fn kerberos_preauth_realms(&self) -> &[String] {
        &self.inner.kerberos_preauth_realms
    }

    /// The settings revision, incremented by every settings write.
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.revision)
    }

    /// The relay site table revision, incremented by every replacement of
    /// the table.
    async fn relay_revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.relay_revision)
    }
}

/// The settable device identification settings of a customer.
#[derive(InputObject)]
struct DaiCustomerSettingsInput {
    /// Whether device account identification is enabled.
    device_account_identification: bool,
    /// The multiple of a lease time after which a device with a lease is
    /// inactive; at least 1.
    inactivity_multiplier: u32,
    /// The time, in seconds, after which a device without a lease is
    /// inactive; at least 1.
    no_lease_inactivity_secs: StringNumber<u64>,
    /// The time, in seconds, after which evidence ages out; at least 1.
    evidence_aging_secs: StringNumber<u64>,
    /// The Kerberos realms confirmed to enforce pre-authentication; each
    /// non-empty.
    kerberos_preauth_realms: Vec<String>,
}
