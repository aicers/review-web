use std::sync::Arc;

use async_graphql::{Context, Object, Result, SimpleObject};
use tokio::sync::Notify;
use tracing::info;

use super::{CertManager, Role, RoleGuard};
use crate::info_with_username;

#[derive(Debug, SimpleObject)]
struct CertificatePayload {
    parsed_certificate: Vec<ParsedCertificate>,
}

#[derive(Debug, SimpleObject)]
pub struct ParsedCertificate {
    pub common_name: Option<String>,
    pub subject_alternative_name: Option<Vec<String>>,
}

#[derive(Default)]
pub(super) struct CertMutation;

#[Object]
impl CertMutation {
    /// Updates the server certificate.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_certificate(
        &self,
        ctx: &Context<'_>,
        cert: String,
        key: String,
    ) -> Result<CertificatePayload> {
        info_with_username!(
            ctx,
            "Received a request to update certificate and private key"
        );

        let cert_manager = ctx.data::<Arc<dyn CertManager>>()?;
        let parsed_certs = cert_manager.update_certificate(cert, key)?;

        let tls_reload_handle = ctx.data::<Arc<Notify>>()?;
        tls_reload_handle.notify_waiters();

        Ok(CertificatePayload {
            parsed_certificate: parsed_certs,
        })
    }
}
