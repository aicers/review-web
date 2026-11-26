//! The GraphQL types of raw event bodies, one per review-protocol
//! `RawEventBody` variant, each exposing every field of its body struct
//! except the endpoint host header `endpoint` and `ProcessCreate`'s
//! `logon_id_full`.
//!
//! An integer type wider than a signed 32-bit integer is a `StringNumber`,
//! so that every value keeps its full range.

use async_graphql::{Object, SimpleObject, StringNumber, Union};
use review_protocol::types::{self as protocol, raw_event};

/// The body of the raw event a detection event is about.
#[derive(Union)]
pub(super) enum RawEventBody<'a> {
    Conn(ConnBody<'a>),
    Dns(DnsBody<'a>),
    Http(HttpBody<'a>),
    Rdp(RdpBody<'a>),
    Smtp(SmtpBody<'a>),
    Ntlm(NtlmBody<'a>),
    Kerberos(KerberosBody<'a>),
    Ssh(SshBody<'a>),
    DceRpc(DceRpcBody<'a>),
    Ftp(FtpBody<'a>),
    Mqtt(MqttBody<'a>),
    Ldap(LdapBody<'a>),
    Tls(TlsBody<'a>),
    Smb(SmbBody<'a>),
    Nfs(NfsBody<'a>),
    Bootp(BootpBody<'a>),
    Dhcp(DhcpBody<'a>),
    Radius(RadiusBody<'a>),
    MalformedDns(MalformedDnsBody<'a>),
    Icmp(IcmpBody<'a>),
    ProcessCreate(ProcessCreateBody<'a>),
    FileCreateTime(FileCreateTimeBody<'a>),
    NetworkConnect(NetworkConnectBody<'a>),
    ProcessTerminate(ProcessTerminateBody<'a>),
    ImageLoad(ImageLoadBody<'a>),
    FileCreate(FileCreateBody<'a>),
    RegistryValueSet(RegistryValueSetBody<'a>),
    RegistryKeyRename(RegistryKeyRenameBody<'a>),
    FileCreateStreamHash(FileCreateStreamHashBody<'a>),
    PipeEvent(PipeEventBody<'a>),
    DnsQuery(DnsQueryBody<'a>),
    FileDelete(FileDeleteBody<'a>),
    ProcessTamper(ProcessTamperBody<'a>),
    FileDeleteDetected(FileDeleteDetectedBody<'a>),
    Netflow5(Netflow5Body<'a>),
    Netflow9(Netflow9Body<'a>),
}

impl<'a> TryFrom<&'a protocol::RawEventBody> for RawEventBody<'a> {
    type Error = async_graphql::Error;

    /// Fails for a body kind this schema has no type for.
    fn try_from(body: &'a protocol::RawEventBody) -> Result<Self, Self::Error> {
        // No wildcard arm: a body added to review-protocol must be mapped.
        Ok(match body {
            protocol::RawEventBody::Conn(body) => Self::Conn(ConnBody(body)),
            protocol::RawEventBody::Dns(body) => Self::Dns(DnsBody(body)),
            protocol::RawEventBody::Http(body) => Self::Http(HttpBody(body)),
            protocol::RawEventBody::Rdp(body) => Self::Rdp(RdpBody(body)),
            protocol::RawEventBody::Smtp(body) => Self::Smtp(SmtpBody(body)),
            protocol::RawEventBody::Ntlm(body) => Self::Ntlm(NtlmBody(body)),
            protocol::RawEventBody::Kerberos(body) => Self::Kerberos(KerberosBody(body)),
            protocol::RawEventBody::Ssh(body) => Self::Ssh(SshBody(body)),
            protocol::RawEventBody::DceRpc(body) => Self::DceRpc(DceRpcBody(body)),
            protocol::RawEventBody::Ftp(body) => Self::Ftp(FtpBody(body)),
            protocol::RawEventBody::Mqtt(body) => Self::Mqtt(MqttBody(body)),
            protocol::RawEventBody::Ldap(body) => Self::Ldap(LdapBody(body)),
            protocol::RawEventBody::Tls(body) => Self::Tls(TlsBody(body)),
            protocol::RawEventBody::Smb(body) => Self::Smb(SmbBody(body)),
            protocol::RawEventBody::Nfs(body) => Self::Nfs(NfsBody(body)),
            protocol::RawEventBody::Bootp(body) => Self::Bootp(BootpBody(body)),
            protocol::RawEventBody::Dhcp(body) => Self::Dhcp(DhcpBody(body)),
            protocol::RawEventBody::Radius(body) => Self::Radius(RadiusBody(body)),
            protocol::RawEventBody::MalformedDns(body) => {
                Self::MalformedDns(MalformedDnsBody(body))
            }
            protocol::RawEventBody::Icmp(body) => Self::Icmp(IcmpBody(body)),
            protocol::RawEventBody::ProcessCreate(body) => {
                Self::ProcessCreate(ProcessCreateBody(body))
            }
            protocol::RawEventBody::FileCreateTime(body) => {
                Self::FileCreateTime(FileCreateTimeBody(body))
            }
            protocol::RawEventBody::NetworkConnect(body) => {
                Self::NetworkConnect(NetworkConnectBody(body))
            }
            protocol::RawEventBody::ProcessTerminate(body) => {
                Self::ProcessTerminate(ProcessTerminateBody(body))
            }
            protocol::RawEventBody::ImageLoad(body) => Self::ImageLoad(ImageLoadBody(body)),
            protocol::RawEventBody::FileCreate(body) => Self::FileCreate(FileCreateBody(body)),
            protocol::RawEventBody::RegistryValueSet(body) => {
                Self::RegistryValueSet(RegistryValueSetBody(body))
            }
            protocol::RawEventBody::RegistryKeyRename(body) => {
                Self::RegistryKeyRename(RegistryKeyRenameBody(body))
            }
            protocol::RawEventBody::FileCreateStreamHash(body) => {
                Self::FileCreateStreamHash(FileCreateStreamHashBody(body))
            }
            protocol::RawEventBody::PipeEvent(body) => Self::PipeEvent(PipeEventBody(body)),
            protocol::RawEventBody::DnsQuery(body) => Self::DnsQuery(DnsQueryBody(body)),
            protocol::RawEventBody::FileDelete(body) => Self::FileDelete(FileDeleteBody(body)),
            protocol::RawEventBody::ProcessTamper(body) => {
                Self::ProcessTamper(ProcessTamperBody(body))
            }
            protocol::RawEventBody::FileDeleteDetected(body) => {
                Self::FileDeleteDetected(FileDeleteDetectedBody(body))
            }
            protocol::RawEventBody::Netflow5(body) => Self::Netflow5(Netflow5Body(body)),
            protocol::RawEventBody::Netflow9(body) => Self::Netflow9(Netflow9Body(body)),
            protocol::RawEventBody::DriverLoad(_)
            | protocol::RawEventBody::CreateRemoteThread(_)
            | protocol::RawEventBody::RawAccessRead(_)
            | protocol::RawEventBody::ProcessAccess(_)
            | protocol::RawEventBody::RegistryObjectAddDel(_)
            | protocol::RawEventBody::WindowsEventLog(_)
            | protocol::RawEventBody::Journald(_)
            | protocol::RawEventBody::Auditd(_) => {
                return Err("the raw event body of this kind is not supported".into());
            }
        })
    }
}

/// The `Conn` raw event body.
pub(super) struct ConnBody<'a>(&'a raw_event::Conn);

#[Object]
impl ConnBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn conn_state(&self) -> &str {
        &self.0.conn_state
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn service(&self) -> &str {
        &self.0.service
    }

    async fn orig_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_bytes)
    }

    async fn resp_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_bytes)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }
}

/// The `Dns` raw event body.
pub(super) struct DnsBody<'a>(&'a raw_event::Dns);

#[Object]
impl DnsBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn query(&self) -> &str {
        &self.0.query
    }

    async fn answer(&self) -> &[String] {
        &self.0.answer
    }

    async fn trans_id(&self) -> u16 {
        self.0.trans_id
    }

    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.0.rtt)
    }

    async fn qclass(&self) -> u16 {
        self.0.qclass
    }

    async fn qtype(&self) -> u16 {
        self.0.qtype
    }

    async fn rcode(&self) -> u16 {
        self.0.rcode
    }

    async fn aa_flag(&self) -> bool {
        self.0.aa_flag
    }

    async fn tc_flag(&self) -> bool {
        self.0.tc_flag
    }

    async fn rd_flag(&self) -> bool {
        self.0.rd_flag
    }

    async fn ra_flag(&self) -> bool {
        self.0.ra_flag
    }

    async fn ttl(&self) -> &[i32] {
        &self.0.ttl
    }
}

/// The `Http` raw event body.
pub(super) struct HttpBody<'a>(&'a raw_event::Http);

#[Object]
impl HttpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn method(&self) -> &str {
        &self.0.method
    }

    async fn host(&self) -> &str {
        &self.0.host
    }

    async fn uri(&self) -> &str {
        &self.0.uri
    }

    async fn referer(&self) -> &str {
        &self.0.referer
    }

    async fn version(&self) -> &str {
        &self.0.version
    }

    async fn user_agent(&self) -> &str {
        &self.0.user_agent
    }

    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.0.request_len)
    }

    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.0.response_len)
    }

    async fn status_code(&self) -> u16 {
        self.0.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.0.status_msg
    }

    async fn username(&self) -> &str {
        &self.0.username
    }

    async fn password(&self) -> &str {
        &self.0.password
    }

    async fn cookie(&self) -> &str {
        &self.0.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.0.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.0.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.0.cache_control
    }

    async fn filenames(&self) -> &[String] {
        &self.0.filenames
    }

    async fn mime_types(&self) -> &[String] {
        &self.0.mime_types
    }

    async fn body(&self) -> &[u8] {
        &self.0.body
    }

    async fn state(&self) -> &str {
        &self.0.state
    }
}

/// The `Rdp` raw event body.
pub(super) struct RdpBody<'a>(&'a raw_event::Rdp);

#[Object]
impl RdpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn cookie(&self) -> &str {
        &self.0.cookie
    }
}

/// The `Smtp` raw event body.
pub(super) struct SmtpBody<'a>(&'a raw_event::Smtp);

#[Object]
impl SmtpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn mailfrom(&self) -> &str {
        &self.0.mailfrom
    }

    async fn date(&self) -> &str {
        &self.0.date
    }

    async fn from(&self) -> &str {
        &self.0.from
    }

    async fn to(&self) -> &str {
        &self.0.to
    }

    async fn subject(&self) -> &str {
        &self.0.subject
    }

    async fn agent(&self) -> &str {
        &self.0.agent
    }

    async fn state(&self) -> &str {
        &self.0.state
    }
}

/// The `Ntlm` raw event body.
pub(super) struct NtlmBody<'a>(&'a raw_event::Ntlm);

#[Object]
impl NtlmBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn protocol(&self) -> &str {
        &self.0.protocol
    }

    async fn username(&self) -> &str {
        &self.0.username
    }

    async fn hostname(&self) -> &str {
        &self.0.hostname
    }

    async fn domainname(&self) -> &str {
        &self.0.domainname
    }

    async fn success(&self) -> &str {
        &self.0.success
    }
}

/// The `Kerberos` raw event body.
pub(super) struct KerberosBody<'a>(&'a raw_event::Kerberos);

#[Object]
impl KerberosBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn client_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.client_time)
    }

    async fn server_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.server_time)
    }

    async fn error_code(&self) -> StringNumber<u32> {
        StringNumber(self.0.error_code)
    }

    async fn client_realm(&self) -> &str {
        &self.0.client_realm
    }

    async fn cname_type(&self) -> u8 {
        self.0.cname_type
    }

    async fn cname(&self) -> &[String] {
        &self.0.cname
    }

    async fn realm(&self) -> &str {
        &self.0.realm
    }

    async fn sname_type(&self) -> u8 {
        self.0.sname_type
    }

    async fn sname(&self) -> &[String] {
        &self.0.sname
    }
}

/// The `Ssh` raw event body.
pub(super) struct SshBody<'a>(&'a raw_event::Ssh);

#[Object]
impl SshBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn client(&self) -> &str {
        &self.0.client
    }

    async fn server(&self) -> &str {
        &self.0.server
    }

    async fn cipher_alg(&self) -> &str {
        &self.0.cipher_alg
    }

    async fn mac_alg(&self) -> &str {
        &self.0.mac_alg
    }

    async fn compression_alg(&self) -> &str {
        &self.0.compression_alg
    }

    async fn kex_alg(&self) -> &str {
        &self.0.kex_alg
    }

    async fn host_key_alg(&self) -> &str {
        &self.0.host_key_alg
    }

    async fn hassh_algorithms(&self) -> &str {
        &self.0.hassh_algorithms
    }

    async fn hassh(&self) -> &str {
        &self.0.hassh
    }

    async fn hassh_server_algorithms(&self) -> &str {
        &self.0.hassh_server_algorithms
    }

    async fn hassh_server(&self) -> &str {
        &self.0.hassh_server
    }

    async fn client_shka(&self) -> &str {
        &self.0.client_shka
    }

    async fn server_shka(&self) -> &str {
        &self.0.server_shka
    }
}

/// The `DceRpc` raw event body.
pub(super) struct DceRpcBody<'a>(&'a raw_event::DceRpc);

#[Object]
impl DceRpcBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn context(&self) -> Vec<DceRpcContext<'_>> {
        self.0.context.iter().map(DceRpcContext).collect()
    }

    async fn request(&self) -> &[String] {
        &self.0.request
    }
}

/// The `Ftp` raw event body.
pub(super) struct FtpBody<'a>(&'a raw_event::Ftp);

#[Object]
impl FtpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn user(&self) -> &str {
        &self.0.user
    }

    async fn password(&self) -> &str {
        &self.0.password
    }

    async fn commands(&self) -> Vec<FtpCommand<'_>> {
        self.0.commands.iter().map(FtpCommand).collect()
    }
}

/// The `Mqtt` raw event body.
pub(super) struct MqttBody<'a>(&'a raw_event::Mqtt);

#[Object]
impl MqttBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn protocol(&self) -> &str {
        &self.0.protocol
    }

    async fn version(&self) -> u8 {
        self.0.version
    }

    async fn client_id(&self) -> &str {
        &self.0.client_id
    }

    async fn connack_reason(&self) -> u8 {
        self.0.connack_reason
    }

    async fn subscribe(&self) -> &[String] {
        &self.0.subscribe
    }

    async fn suback_reason(&self) -> &[u8] {
        &self.0.suback_reason
    }
}

/// The `Ldap` raw event body.
pub(super) struct LdapBody<'a>(&'a raw_event::Ldap);

#[Object]
impl LdapBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn message_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.message_id)
    }

    async fn version(&self) -> u8 {
        self.0.version
    }

    async fn opcode(&self) -> &[String] {
        &self.0.opcode
    }

    async fn result(&self) -> &[String] {
        &self.0.result
    }

    async fn diagnostic_message(&self) -> &[String] {
        &self.0.diagnostic_message
    }

    async fn object(&self) -> &[String] {
        &self.0.object
    }

    async fn argument(&self) -> &[String] {
        &self.0.argument
    }
}

/// The `Tls` raw event body.
pub(super) struct TlsBody<'a>(&'a raw_event::Tls);

#[Object]
impl TlsBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn server_name(&self) -> &str {
        &self.0.server_name
    }

    async fn alpn_protocol(&self) -> &str {
        &self.0.alpn_protocol
    }

    async fn ja3(&self) -> &str {
        &self.0.ja3
    }

    async fn version(&self) -> &str {
        &self.0.version
    }

    async fn client_cipher_suites(&self) -> &[u16] {
        &self.0.client_cipher_suites
    }

    async fn client_extensions(&self) -> &[u16] {
        &self.0.client_extensions
    }

    async fn cipher(&self) -> u16 {
        self.0.cipher
    }

    async fn extensions(&self) -> &[u16] {
        &self.0.extensions
    }

    async fn ja3s(&self) -> &str {
        &self.0.ja3s
    }

    async fn serial(&self) -> &str {
        &self.0.serial
    }

    async fn subject_country(&self) -> &str {
        &self.0.subject_country
    }

    async fn subject_org_name(&self) -> &str {
        &self.0.subject_org_name
    }

    async fn subject_common_name(&self) -> &str {
        &self.0.subject_common_name
    }

    async fn validity_not_before(&self) -> StringNumber<i64> {
        StringNumber(self.0.validity_not_before)
    }

    async fn validity_not_after(&self) -> StringNumber<i64> {
        StringNumber(self.0.validity_not_after)
    }

    async fn subject_alt_name(&self) -> &str {
        &self.0.subject_alt_name
    }

    async fn issuer_country(&self) -> &str {
        &self.0.issuer_country
    }

    async fn issuer_org_name(&self) -> &str {
        &self.0.issuer_org_name
    }

    async fn issuer_org_unit_name(&self) -> &str {
        &self.0.issuer_org_unit_name
    }

    async fn issuer_common_name(&self) -> &str {
        &self.0.issuer_common_name
    }

    async fn last_alert(&self) -> u8 {
        self.0.last_alert
    }
}

/// The `Smb` raw event body.
pub(super) struct SmbBody<'a>(&'a raw_event::Smb);

#[Object]
impl SmbBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn command(&self) -> u8 {
        self.0.command
    }

    async fn path(&self) -> &str {
        &self.0.path
    }

    async fn service(&self) -> &str {
        &self.0.service
    }

    async fn file_name(&self) -> &str {
        &self.0.file_name
    }

    async fn file_size(&self) -> StringNumber<u64> {
        StringNumber(self.0.file_size)
    }

    async fn resource_type(&self) -> u16 {
        self.0.resource_type
    }

    async fn fid(&self) -> u16 {
        self.0.fid
    }

    async fn create_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.create_time)
    }

    async fn access_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.access_time)
    }

    async fn write_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.write_time)
    }

    async fn change_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.change_time)
    }
}

/// The `Nfs` raw event body.
pub(super) struct NfsBody<'a>(&'a raw_event::Nfs);

#[Object]
impl NfsBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn read_files(&self) -> &[String] {
        &self.0.read_files
    }

    async fn write_files(&self) -> &[String] {
        &self.0.write_files
    }
}

/// The `Bootp` raw event body.
pub(super) struct BootpBody<'a>(&'a raw_event::Bootp);

#[Object]
impl BootpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn op(&self) -> u8 {
        self.0.op
    }

    async fn htype(&self) -> u8 {
        self.0.htype
    }

    async fn hops(&self) -> u8 {
        self.0.hops
    }

    async fn xid(&self) -> StringNumber<u32> {
        StringNumber(self.0.xid)
    }

    async fn ciaddr(&self) -> String {
        self.0.ciaddr.to_string()
    }

    async fn yiaddr(&self) -> String {
        self.0.yiaddr.to_string()
    }

    async fn siaddr(&self) -> String {
        self.0.siaddr.to_string()
    }

    async fn giaddr(&self) -> String {
        self.0.giaddr.to_string()
    }

    async fn chaddr(&self) -> &[u8] {
        &self.0.chaddr
    }

    async fn sname(&self) -> &str {
        &self.0.sname
    }

    async fn file(&self) -> &str {
        &self.0.file
    }
}

/// The `Dhcp` raw event body.
pub(super) struct DhcpBody<'a>(&'a raw_event::Dhcp);

#[Object]
impl DhcpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn msg_type(&self) -> u8 {
        self.0.msg_type
    }

    async fn ciaddr(&self) -> String {
        self.0.ciaddr.to_string()
    }

    async fn yiaddr(&self) -> String {
        self.0.yiaddr.to_string()
    }

    async fn siaddr(&self) -> String {
        self.0.siaddr.to_string()
    }

    async fn giaddr(&self) -> String {
        self.0.giaddr.to_string()
    }

    async fn subnet_mask(&self) -> String {
        self.0.subnet_mask.to_string()
    }

    async fn router(&self) -> Vec<String> {
        self.0.router.iter().map(ToString::to_string).collect()
    }

    async fn domain_name_server(&self) -> Vec<String> {
        self.0
            .domain_name_server
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    async fn req_ip_addr(&self) -> String {
        self.0.req_ip_addr.to_string()
    }

    async fn lease_time(&self) -> StringNumber<u32> {
        StringNumber(self.0.lease_time)
    }

    async fn server_id(&self) -> String {
        self.0.server_id.to_string()
    }

    async fn param_req_list(&self) -> &[u8] {
        &self.0.param_req_list
    }

    async fn message(&self) -> &str {
        &self.0.message
    }

    async fn renewal_time(&self) -> StringNumber<u32> {
        StringNumber(self.0.renewal_time)
    }

    async fn rebinding_time(&self) -> StringNumber<u32> {
        StringNumber(self.0.rebinding_time)
    }

    async fn class_id(&self) -> &[u8] {
        &self.0.class_id
    }

    async fn client_id_type(&self) -> u8 {
        self.0.client_id_type
    }

    async fn client_id(&self) -> &[u8] {
        &self.0.client_id
    }

    async fn options(&self) -> Vec<DhcpOption<'_>> {
        self.0
            .options
            .iter()
            .map(|(code, value)| DhcpOption { code: *code, value })
            .collect()
    }
}

/// The `Radius` raw event body.
pub(super) struct RadiusBody<'a>(&'a raw_event::Radius);

#[Object]
impl RadiusBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn id(&self) -> u8 {
        self.0.id
    }

    async fn code(&self) -> u8 {
        self.0.code
    }

    async fn resp_code(&self) -> u8 {
        self.0.resp_code
    }

    async fn auth(&self) -> &str {
        &self.0.auth
    }

    async fn resp_auth(&self) -> &str {
        &self.0.resp_auth
    }

    async fn user_name(&self) -> &[u8] {
        &self.0.user_name
    }

    async fn user_passwd(&self) -> &[u8] {
        &self.0.user_passwd
    }

    async fn chap_passwd(&self) -> &[u8] {
        &self.0.chap_passwd
    }

    async fn nas_ip(&self) -> String {
        self.0.nas_ip.to_string()
    }

    async fn nas_port(&self) -> StringNumber<u32> {
        StringNumber(self.0.nas_port)
    }

    async fn state(&self) -> &[u8] {
        &self.0.state
    }

    async fn nas_id(&self) -> &[u8] {
        &self.0.nas_id
    }

    async fn nas_port_type(&self) -> StringNumber<u32> {
        StringNumber(self.0.nas_port_type)
    }

    async fn message(&self) -> &str {
        &self.0.message
    }
}

/// The `MalformedDns` raw event body.
pub(super) struct MalformedDnsBody<'a>(&'a raw_event::MalformedDns);

#[Object]
impl MalformedDnsBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn trans_id(&self) -> u16 {
        self.0.trans_id
    }

    async fn flags(&self) -> u16 {
        self.0.flags
    }

    async fn question_count(&self) -> u16 {
        self.0.question_count
    }

    async fn answer_count(&self) -> u16 {
        self.0.answer_count
    }

    async fn authority_count(&self) -> u16 {
        self.0.authority_count
    }

    async fn additional_count(&self) -> u16 {
        self.0.additional_count
    }

    async fn query_count(&self) -> StringNumber<u32> {
        StringNumber(self.0.query_count)
    }

    async fn resp_count(&self) -> StringNumber<u32> {
        StringNumber(self.0.resp_count)
    }

    async fn query_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.query_bytes)
    }

    async fn resp_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_bytes)
    }

    async fn query_body(&self) -> &[Vec<u8>] {
        &self.0.query_body
    }

    async fn resp_body(&self) -> &[Vec<u8>] {
        &self.0.resp_body
    }
}

/// The `Icmp` raw event body.
pub(super) struct IcmpBody<'a>(&'a raw_event::Icmp);

#[Object]
impl IcmpBody<'_> {
    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn start_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.start_time)
    }

    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.0.duration)
    }

    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_pkts)
    }

    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_pkts)
    }

    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.orig_l2_bytes)
    }

    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.0.resp_l2_bytes)
    }

    async fn icmp_type(&self) -> u8 {
        self.0.icmp_type
    }

    async fn icmp_code(&self) -> u8 {
        self.0.icmp_code
    }

    async fn id(&self) -> u16 {
        self.0.id
    }

    async fn seq_num(&self) -> u16 {
        self.0.seq_num
    }

    async fn data_len(&self) -> u16 {
        self.0.data_len
    }

    async fn payload(&self) -> &[u8] {
        &self.0.payload
    }
}

/// The `ProcessCreate` raw event body.
pub(super) struct ProcessCreateBody<'a>(&'a raw_event::ProcessCreate);

#[Object]
impl ProcessCreateBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn file_version(&self) -> &str {
        &self.0.file_version
    }

    async fn description(&self) -> &str {
        &self.0.description
    }

    async fn product(&self) -> &str {
        &self.0.product
    }

    async fn company(&self) -> &str {
        &self.0.company
    }

    async fn original_file_name(&self) -> &str {
        &self.0.original_file_name
    }

    async fn command_line(&self) -> &str {
        &self.0.command_line
    }

    async fn current_directory(&self) -> &str {
        &self.0.current_directory
    }

    async fn user(&self) -> &str {
        &self.0.user
    }

    async fn logon_guid(&self) -> &str {
        &self.0.logon_guid
    }

    async fn logon_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.logon_id)
    }

    async fn terminal_session_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.terminal_session_id)
    }

    async fn integrity_level(&self) -> &str {
        &self.0.integrity_level
    }

    async fn hashes(&self) -> &[String] {
        &self.0.hashes
    }

    async fn parent_process_guid(&self) -> &str {
        &self.0.parent_process_guid
    }

    async fn parent_process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.parent_process_id)
    }

    async fn parent_image(&self) -> &str {
        &self.0.parent_image
    }

    async fn parent_command_line(&self) -> &str {
        &self.0.parent_command_line
    }

    async fn parent_user(&self) -> &str {
        &self.0.parent_user
    }
}

/// The `FileCreateTime` raw event body.
pub(super) struct FileCreateTimeBody<'a>(&'a raw_event::FileCreateTime);

#[Object]
impl FileCreateTimeBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_filename(&self) -> &str {
        &self.0.target_filename
    }

    async fn creation_utc_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.creation_utc_time)
    }

    async fn previous_creation_utc_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.previous_creation_utc_time)
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `NetworkConnect` raw event body.
pub(super) struct NetworkConnectBody<'a>(&'a raw_event::NetworkConnect);

#[Object]
impl NetworkConnectBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn user(&self) -> &str {
        &self.0.user
    }

    async fn protocol(&self) -> &str {
        &self.0.protocol
    }

    async fn initiated(&self) -> bool {
        self.0.initiated
    }

    async fn source_is_ipv6(&self) -> bool {
        self.0.source_is_ipv6
    }

    async fn source_ip(&self) -> String {
        self.0.source_ip.to_string()
    }

    async fn source_hostname(&self) -> &str {
        &self.0.source_hostname
    }

    async fn source_port(&self) -> u16 {
        self.0.source_port
    }

    async fn source_port_name(&self) -> &str {
        &self.0.source_port_name
    }

    async fn destination_is_ipv6(&self) -> bool {
        self.0.destination_is_ipv6
    }

    async fn destination_ip(&self) -> String {
        self.0.destination_ip.to_string()
    }

    async fn destination_hostname(&self) -> &str {
        &self.0.destination_hostname
    }

    async fn destination_port(&self) -> u16 {
        self.0.destination_port
    }

    async fn destination_port_name(&self) -> &str {
        &self.0.destination_port_name
    }
}

/// The `ProcessTerminate` raw event body.
pub(super) struct ProcessTerminateBody<'a>(&'a raw_event::ProcessTerminate);

#[Object]
impl ProcessTerminateBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `ImageLoad` raw event body.
pub(super) struct ImageLoadBody<'a>(&'a raw_event::ImageLoad);

#[Object]
impl ImageLoadBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn image_loaded(&self) -> &str {
        &self.0.image_loaded
    }

    async fn file_version(&self) -> &str {
        &self.0.file_version
    }

    async fn description(&self) -> &str {
        &self.0.description
    }

    async fn product(&self) -> &str {
        &self.0.product
    }

    async fn company(&self) -> &str {
        &self.0.company
    }

    async fn original_file_name(&self) -> &str {
        &self.0.original_file_name
    }

    async fn hashes(&self) -> &[String] {
        &self.0.hashes
    }

    async fn signed(&self) -> bool {
        self.0.signed
    }

    async fn signature(&self) -> &str {
        &self.0.signature
    }

    async fn signature_status(&self) -> &str {
        &self.0.signature_status
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `FileCreate` raw event body.
pub(super) struct FileCreateBody<'a>(&'a raw_event::FileCreate);

#[Object]
impl FileCreateBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_filename(&self) -> &str {
        &self.0.target_filename
    }

    async fn creation_utc_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.creation_utc_time)
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `RegistryValueSet` raw event body.
pub(super) struct RegistryValueSetBody<'a>(&'a raw_event::RegistryValueSet);

#[Object]
impl RegistryValueSetBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn event_type(&self) -> &str {
        &self.0.event_type
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_object(&self) -> &str {
        &self.0.target_object
    }

    async fn details(&self) -> &str {
        &self.0.details
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `RegistryKeyRename` raw event body.
pub(super) struct RegistryKeyRenameBody<'a>(&'a raw_event::RegistryKeyRename);

#[Object]
impl RegistryKeyRenameBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn event_type(&self) -> &str {
        &self.0.event_type
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_object(&self) -> &str {
        &self.0.target_object
    }

    async fn new_name(&self) -> &str {
        &self.0.new_name
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `FileCreateStreamHash` raw event body.
pub(super) struct FileCreateStreamHashBody<'a>(&'a raw_event::FileCreateStreamHash);

#[Object]
impl FileCreateStreamHashBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_filename(&self) -> &str {
        &self.0.target_filename
    }

    async fn creation_utc_time(&self) -> StringNumber<i64> {
        StringNumber(self.0.creation_utc_time)
    }

    async fn hash(&self) -> &[String] {
        &self.0.hash
    }

    async fn contents(&self) -> &str {
        &self.0.contents
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `PipeEvent` raw event body.
pub(super) struct PipeEventBody<'a>(&'a raw_event::PipeEvent);

#[Object]
impl PipeEventBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn event_type(&self) -> &str {
        &self.0.event_type
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn pipe_name(&self) -> &str {
        &self.0.pipe_name
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `DnsQuery` raw event body.
pub(super) struct DnsQueryBody<'a>(&'a raw_event::DnsQuery);

#[Object]
impl DnsQueryBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn query_name(&self) -> &str {
        &self.0.query_name
    }

    async fn query_status(&self) -> StringNumber<u32> {
        StringNumber(self.0.query_status)
    }

    async fn query_results(&self) -> &[String] {
        &self.0.query_results
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `FileDelete` raw event body.
pub(super) struct FileDeleteBody<'a>(&'a raw_event::FileDelete);

#[Object]
impl FileDeleteBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn user(&self) -> &str {
        &self.0.user
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_filename(&self) -> &str {
        &self.0.target_filename
    }

    async fn hashes(&self) -> &[String] {
        &self.0.hashes
    }

    async fn is_executable(&self) -> bool {
        self.0.is_executable
    }

    async fn archived(&self) -> bool {
        self.0.archived
    }
}

/// The `ProcessTamper` raw event body.
pub(super) struct ProcessTamperBody<'a>(&'a raw_event::ProcessTamper);

#[Object]
impl ProcessTamperBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn tamper_type(&self) -> &str {
        &self.0.tamper_type
    }

    async fn user(&self) -> &str {
        &self.0.user
    }
}

/// The `FileDeleteDetected` raw event body.
pub(super) struct FileDeleteDetectedBody<'a>(&'a raw_event::FileDeleteDetected);

#[Object]
impl FileDeleteDetectedBody<'_> {
    async fn agent_name(&self) -> &str {
        &self.0.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.0.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.0.process_guid
    }

    async fn process_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.process_id)
    }

    async fn user(&self) -> &str {
        &self.0.user
    }

    async fn image(&self) -> &str {
        &self.0.image
    }

    async fn target_filename(&self) -> &str {
        &self.0.target_filename
    }

    async fn hashes(&self) -> &[String] {
        &self.0.hashes
    }

    async fn is_executable(&self) -> bool {
        self.0.is_executable
    }
}

/// The `Netflow5` raw event body.
pub(super) struct Netflow5Body<'a>(&'a raw_event::Netflow5);

#[Object]
impl Netflow5Body<'_> {
    async fn src_addr(&self) -> String {
        self.0.src_addr.to_string()
    }

    async fn dst_addr(&self) -> String {
        self.0.dst_addr.to_string()
    }

    async fn next_hop(&self) -> String {
        self.0.next_hop.to_string()
    }

    async fn input(&self) -> u16 {
        self.0.input
    }

    async fn output(&self) -> u16 {
        self.0.output
    }

    async fn d_pkts(&self) -> StringNumber<u32> {
        StringNumber(self.0.d_pkts)
    }

    async fn d_octets(&self) -> StringNumber<u32> {
        StringNumber(self.0.d_octets)
    }

    async fn first(&self) -> StringNumber<u32> {
        StringNumber(self.0.first)
    }

    async fn last(&self) -> StringNumber<u32> {
        StringNumber(self.0.last)
    }

    async fn src_port(&self) -> u16 {
        self.0.src_port
    }

    async fn dst_port(&self) -> u16 {
        self.0.dst_port
    }

    async fn tcp_flags(&self) -> u8 {
        self.0.tcp_flags
    }

    async fn prot(&self) -> u8 {
        self.0.prot
    }

    async fn tos(&self) -> u8 {
        self.0.tos
    }

    async fn src_as(&self) -> u16 {
        self.0.src_as
    }

    async fn dst_as(&self) -> u16 {
        self.0.dst_as
    }

    async fn src_mask(&self) -> u8 {
        self.0.src_mask
    }

    async fn dst_mask(&self) -> u8 {
        self.0.dst_mask
    }

    async fn sequence(&self) -> StringNumber<u32> {
        StringNumber(self.0.sequence)
    }

    async fn engine_type(&self) -> u8 {
        self.0.engine_type
    }

    async fn engine_id(&self) -> u8 {
        self.0.engine_id
    }

    async fn sampling_mode(&self) -> u8 {
        self.0.sampling_mode
    }

    async fn sampling_rate(&self) -> u16 {
        self.0.sampling_rate
    }
}

/// The `Netflow9` raw event body.
pub(super) struct Netflow9Body<'a>(&'a raw_event::Netflow9);

#[Object]
impl Netflow9Body<'_> {
    async fn sequence(&self) -> StringNumber<u32> {
        StringNumber(self.0.sequence)
    }

    async fn source_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.source_id)
    }

    async fn template_id(&self) -> u16 {
        self.0.template_id
    }

    async fn orig_addr(&self) -> String {
        self.0.orig_addr.to_string()
    }

    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_addr(&self) -> String {
        self.0.resp_addr.to_string()
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn contents(&self) -> &str {
        &self.0.contents
    }
}

/// A presentation context of a DCE/RPC raw event.
pub(super) struct DceRpcContext<'a>(&'a raw_event::DceRpcContext);

#[Object]
impl DceRpcContext<'_> {
    async fn id(&self) -> u16 {
        self.0.id
    }

    async fn abstract_syntax(&self) -> StringNumber<u128> {
        StringNumber(self.0.abstract_syntax)
    }

    async fn abstract_major(&self) -> u16 {
        self.0.abstract_major
    }

    async fn abstract_minor(&self) -> u16 {
        self.0.abstract_minor
    }

    async fn transfer_syntax(&self) -> StringNumber<u128> {
        StringNumber(self.0.transfer_syntax)
    }

    async fn transfer_major(&self) -> u16 {
        self.0.transfer_major
    }

    async fn transfer_minor(&self) -> u16 {
        self.0.transfer_minor
    }

    async fn acceptance(&self) -> u16 {
        self.0.acceptance
    }

    async fn reason(&self) -> u16 {
        self.0.reason
    }
}

/// A command of an FTP raw event.
pub(super) struct FtpCommand<'a>(&'a raw_event::FtpCommand);

#[Object]
impl FtpCommand<'_> {
    async fn command(&self) -> &str {
        &self.0.command
    }

    async fn reply_code(&self) -> &str {
        &self.0.reply_code
    }

    async fn reply_msg(&self) -> &str {
        &self.0.reply_msg
    }

    async fn data_passive(&self) -> bool {
        self.0.data_passive
    }

    async fn data_orig_addr(&self) -> String {
        self.0.data_orig_addr.to_string()
    }

    async fn data_resp_addr(&self) -> String {
        self.0.data_resp_addr.to_string()
    }

    async fn data_resp_port(&self) -> u16 {
        self.0.data_resp_port
    }

    async fn file(&self) -> &str {
        &self.0.file
    }

    async fn file_size(&self) -> StringNumber<u64> {
        StringNumber(self.0.file_size)
    }

    async fn file_id(&self) -> &str {
        &self.0.file_id
    }
}

/// A DHCP option, as the sensor recorded it.
#[derive(SimpleObject)]
pub(super) struct DhcpOption<'a> {
    /// The option code.
    code: u8,
    /// The option payload, byte for byte.
    value: &'a [u8],
}
