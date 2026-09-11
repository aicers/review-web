//! The registry of the platform's own host-fixed infrastructure.
//!
//! A core component — `review`, `aice-web-next`, `roxyd` or `bootroot` — is
//! neither an agent nor an external service, and it is not a child of a node
//! record either. Its listing is therefore a top-level query rather than a
//! field of `Node`: hanging it there would inherit the customer scoping a node
//! read carries, which is the wrong guard for a class that gets no customer
//! scoping precisely because it is control-plane.

use async_graphql::{ComplexObject, Context, Object, Result, SimpleObject};
use review_database::{self as database, Iterable};
use tracing::info;

use super::{
    Role, RoleGuard,
    install_state::{self, Lifecycle, UpdateState},
    operation_attempt::{self, OperationAttempt},
};
use crate::info_with_username;

#[derive(Default)]
pub(super) struct CoreComponentQuery;

#[Object]
impl CoreComponentQuery {
    /// The core-component registry: one entry per `(component, host)`.
    ///
    /// The registry is one row per pair — two singletons plus one `roxyd` and
    /// one `bootroot` per host — so it is a plain list rather than a paginated
    /// connection. The order is the registry's own key order, which is a
    /// deterministic function of `(component, host)`; nothing here re-sorts
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry cannot be read.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn core_component_list(&self, ctx: &Context<'_>) -> Result<Vec<CoreComponent>> {
        info_with_username!(ctx, "Core component list requested");
        let store = super::get_store(ctx)?;
        let map = store.core_component_map();
        map.iter(database::event::Direction::Forward, None)
            .map(|entry| {
                entry
                    .map(|row| CoreComponent::from(&row))
                    .map_err(Into::into)
            })
            .collect()
    }
}

/// A core component installed, or due to be installed, on a host.
#[derive(Clone, SimpleObject)]
#[graphql(complex)]
pub(super) struct CoreComponent {
    /// The canonical package-id: `review`, `aice-web-next`, `roxyd` or
    /// `bootroot`.
    ///
    /// It is itself the package-id the row's build comes from; no
    /// kind-to-package-id mapping is involved on this type.
    component: String,

    /// The host the component is installed on.
    host: String,

    /// The version of the build installed on the host, as the host reports it.
    ///
    /// An opaque display label that is not required to be semver. It is null
    /// together with `installedCommit` or not at all: the two are one build
    /// identity, and half of one names no build.
    installed_version: Option<String>,

    /// The commit of the build installed on the host, as the host reports it.
    ///
    /// Null together with `installedVersion` or not at all.
    installed_commit: Option<String>,

    /// The install and run state of the build on the host.
    ///
    /// It is non-null here, unlike on an agent or an external service: every
    /// core component is package-managed by construction, since `component`
    /// *is* a package-id, so the null that discriminates a kind with no
    /// package has no counterpart on this type.
    lifecycle: Lifecycle,

    /// Whether the row is excluded from update through this product.
    ///
    /// `true` for `bootroot`, the installer-managed trust anchor. Such a row
    /// reports `updateAvailable` `false` whatever it has installed, and the
    /// flag is what lets a client render it as excluded rather than as merely
    /// up to date.
    installer_managed: bool,
}

#[ComplexObject]
impl CoreComponent {
    /// Whether the store holds a build newer than the installed one for this
    /// row's component.
    ///
    /// It is inequality of build identity against `latest_build(component)`,
    /// not an ordering comparison, so a hotfix carrying the same version and a
    /// different commit is `true`. A row with nothing installed, one whose
    /// component has no accepted build, and an `installerManaged` row are all
    /// `false`.
    ///
    /// A `false` here is only "up to date" when `updateCheckFailed` is
    /// `false`; the two must be read together.
    ///
    /// # Errors
    ///
    /// Returns an error if the package deployer is missing from the GraphQL
    /// context. A failed lookup is not an error: it is reported through
    /// `updateCheckFailed`.
    async fn update_available(&self, ctx: &Context<'_>) -> Result<bool> {
        Ok(self.update_state(ctx).await?.available)
    }

    /// Whether this response's lookup of the newest build for this row's
    /// component failed.
    ///
    /// When it is `true`, `updateAvailable` is `false` because nothing was
    /// answered to compare against, and a client must not render that pair as
    /// "up to date". It is `false` for an `installerManaged` row, which
    /// consults no store at all.
    ///
    /// # Errors
    ///
    /// Returns an error if the package deployer is missing from the GraphQL
    /// context.
    async fn update_check_failed(&self, ctx: &Context<'_>) -> Result<bool> {
        Ok(self.update_state(ctx).await?.check_failed)
    }

    /// The current operation attempt for this row's `(host, component)`, or
    /// null if it has none.
    ///
    /// It is the running attempt where there is one, otherwise the attempt
    /// that still owes a compensation, otherwise the last one to finish. That
    /// ordering is `review-database`'s, not this crate's.
    ///
    /// The lookup carries no instance number: a core component's class has no
    /// instance dimension, so its attempts are recorded under none.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger cannot be read.
    async fn latest_operation_attempt(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<OperationAttempt>> {
        operation_attempt::latest_attempt(ctx, &self.host, &self.component, None)
    }
}

impl CoreComponent {
    async fn update_state(&self, ctx: &Context<'_>) -> Result<UpdateState> {
        if self.installer_managed {
            return Ok(UpdateState::NOT_CHECKED);
        }
        install_state::update_state(
            ctx,
            Some(&self.component),
            install_state::installed_identity(
                self.installed_version.as_deref(),
                self.installed_commit.as_deref(),
                Some(self.lifecycle),
            ),
        )
        .await
    }
}

impl From<&database::CoreComponent> for CoreComponent {
    fn from(input: &database::CoreComponent) -> Self {
        // The halves travel together or not at all: nothing in the store
        // enforces that both are written, and half an identity names no build.
        let (installed_version, installed_commit) = install_state::paired_identity(
            input.installed_version.as_deref(),
            input.installed_commit.as_deref(),
        );
        Self {
            component: input.component.clone(),
            host: input.host.clone(),
            installed_version,
            installed_commit,
            lifecycle: input.lifecycle.into(),
            installer_managed: input.installer_managed,
        }
    }
}
