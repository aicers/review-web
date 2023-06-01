use anyhow::{anyhow, bail, Context, Error, Result};
use async_trait::async_trait;
use chrono::NaiveTime;
use config::{Environment, File};
use futures::{
    future::{self, Either},
    pin_mut,
};
use ipnet::IpNet;
use review_database::{backup::BackupConfig, migrate_data_dir, Database, Store};
use review_web::{self as web, graphql::AgentManager, CertManager};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::exit,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{mpsc, Notify, RwLock},
};
use tracing::{error, info, metadata::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

struct MiniCertManager {
    cert: PathBuf,
    key: PathBuf,
}

impl MiniCertManager {
    pub fn new(cert: PathBuf, key: PathBuf) -> Self {
        Self { cert, key }
    }
}

impl CertManager for MiniCertManager {
    fn cert_path(&self) -> async_graphql::Result<std::path::PathBuf, anyhow::Error> {
        Ok(self.cert.clone())
    }

    fn key_path(&self) -> async_graphql::Result<std::path::PathBuf, anyhow::Error> {
        Ok(self.key.clone())
    }

    fn update_certificate(
        &self,
        _cert: String,
        _key: String,
    ) -> async_graphql::Result<Vec<review_web::graphql::ParsedCertificate>, anyhow::Error> {
        bail!("Not supported")
    }
}

struct Manager;

#[async_trait]
impl AgentManager for Manager {
    async fn broadcast_to_crusher(&self, _msg: &[u8]) -> Result<(), Error> {
        bail!("Not supported")
    }

    async fn broadcast_trusted_domains(&self) -> Result<(), Error> {
        bail!("Not supported")
    }

    async fn broadcast_internal_networks(&self, _networks: &[u8]) -> Result<Vec<String>, Error> {
        bail!("Not supported")
    }
    async fn broadcast_allow_networks(&self, _networks: &[u8]) -> Result<Vec<String>, Error> {
        bail!("Not supported")
    }

    async fn broadcast_block_networks(&self, _networks: &[u8]) -> Result<Vec<String>, Error> {
        bail!("Not supported")
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, Error> {
        bail!("Not supported")
    }

    async fn send_and_recv(&self, _key: &str, _msg: &[u8]) -> Result<Vec<u8>, Error> {
        bail!("Not supported")
    }

    async fn update_traffic_filter_rules(
        &self,
        _key: &str,
        _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
    ) -> Result<(), Error> {
        bail!("Not supported")
    }
}

const DEFAULT_DATABASE_URL: &str = "postgres://review@localhost/review";
const DEFAULT_SERVER: &str = "localhost";
const DEFAULT_LOG_PATH: &str = "/data/logs/apps";
const DEFAULT_NUM_OF_BACKUPS: u32 = 5;
const DEFAULT_BACKUP_TIME: &str = "23:59:59"; // format: "%H:%M:%S"
const DEFAULT_BACKUP_DURATION: i16 = 1; // unit: day

pub struct Config {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    log_dir: PathBuf,
    htdocs_dir: PathBuf,
    database_url: String,
    graphql_srv_addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    ca_certs: Vec<PathBuf>,
    ip2location: Option<PathBuf>,
    database_dir: PathBuf,
    database_container: String,
    num_of_backups_to_keep: u32,
    backup_schedule: (Duration, Duration),
    cfg_path: PathBuf,
    reverse_proxies: Vec<review_web::archive::Config>,
}

#[derive(Debug, Deserialize)]
struct ConfigParser {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    log_dir: PathBuf,
    htdocs_dir: PathBuf,
    database_url: String,
    graphql_srv_addr: String,
    cert: PathBuf,
    key: PathBuf,
    ca_certs: Option<Vec<PathBuf>>,
    ip2location: Option<PathBuf>,
    database_dir: PathBuf,
    database_container: String,
    num_of_backups_to_keep: u32,
    backup_time: String,
    backup_duration: u16,
    cfg_path: PathBuf,
    archive: Option<review_web::archive::Config>,
    reverse_proxies: Option<Vec<review_web::archive::Config>>,
}

impl Config {
    pub fn load_config(path: Option<&str>) -> Result<Self> {
        let builder = config::Config::builder()
            .set_default("database_url", DEFAULT_DATABASE_URL)
            .context("cannot set the default database URL")?
            .set_default("graphql_srv_addr", DEFAULT_SERVER)
            .context("cannot set the default GraphQL server address")?
            .set_default("cert", env::current_dir()?.join("cert.pem").to_str())
            .context("cannot set the default certificate file name")?
            .set_default("key", env::current_dir()?.join("key.pem").to_str())
            .context("cannot set the default private key file name")?
            .set_default("data_dir", env::current_dir()?.join("data").to_str())
            .context("cannot set the default data directory")?
            .set_default("backup_dir", env::current_dir()?.join("backup").to_str())
            .context("cannot set the default backup directory")?
            .set_default("log_dir", DEFAULT_LOG_PATH)
            .context("cannot set the default log path")?
            .set_default("htdocs_dir", env::current_dir()?.join("htdocs").to_str())
            .context("cannot set the default web directory")?
            .set_default("database_dir", env::current_dir()?.join("AICE_DB").to_str())
            .context("cannot set the default database directory")?
            .set_default("database_container", "aice_db")
            .context("cannot set the default database container")?
            .set_default("num_of_backups_to_keep", DEFAULT_NUM_OF_BACKUPS)
            .context("cannot set the default num of backups")?
            .set_default("backup_time", DEFAULT_BACKUP_TIME)
            .context("cannot set the default backup schedule time")?
            .set_default("backup_duration", DEFAULT_BACKUP_DURATION)
            .context("cannot set the default backup scheudule time")?
            .set_default("cfg_path", env::current_dir()?.join("config.toml").to_str())
            .context("cannot set the default config file name")?;
        let config: ConfigParser = if let Some(path) = path {
            builder
                .add_source(File::with_name(path))
                .set_override("cfg_path", path)?
        } else {
            builder
        }
        .add_source(Environment::with_prefix("REVIEW"))
        .build()
        .context("cannot build the config")?
        .try_deserialize()?;

        let graphql_srv_addr = config.graphql_srv_addr.parse()?;

        let reverse_proxies = {
            let mut reverse_proxies = config.reverse_proxies.clone().unwrap_or_default();
            if let Some(archive) = config.archive {
                reverse_proxies.push(archive);
            }
            reverse_proxies
        };

        let backup_schedule = {
            let time = NaiveTime::parse_from_str(&config.backup_time, "%H:%M:%S")?;
            let duration = Duration::from_secs(u64::from(config.backup_duration) * 24 * 60 * 60);
            let init = backup_initial(time, duration)?;
            (init, duration)
        };

        Ok(Self {
            data_dir: config.data_dir,
            backup_dir: config.backup_dir,
            log_dir: config.log_dir,
            htdocs_dir: config.htdocs_dir,
            database_url: config.database_url,
            graphql_srv_addr,
            cert: config.cert,
            key: config.key,
            ca_certs: config.ca_certs.unwrap_or_default(),
            ip2location: config.ip2location,
            database_dir: config.database_dir,
            database_container: config.database_container,
            num_of_backups_to_keep: config.num_of_backups_to_keep,
            backup_schedule,
            cfg_path: config.cfg_path,
            reverse_proxies,
        })
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        self.data_dir.as_ref()
    }

    #[must_use]
    pub fn backup_dir(&self) -> &Path {
        self.backup_dir.as_ref()
    }

    #[must_use]
    pub fn log_dir(&self) -> &Path {
        self.log_dir.as_ref()
    }

    #[must_use]
    pub fn htdocs_dir(&self) -> &Path {
        self.htdocs_dir.as_ref()
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub fn graphql_srv_addr(&self) -> SocketAddr {
        self.graphql_srv_addr
    }

    #[must_use]
    pub(crate) fn ca_certs(&self) -> Vec<&Path> {
        self.ca_certs
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect()
    }

    #[must_use]
    pub fn ip2location(&self) -> Option<&Path> {
        self.ip2location.as_deref()
    }

    #[must_use]
    pub fn database_dir(&self) -> &Path {
        self.database_dir.as_ref()
    }

    #[must_use]
    pub fn database_container(&self) -> &str {
        &self.database_container
    }

    #[must_use]
    pub fn num_of_backups_to_keep(&self) -> u32 {
        self.num_of_backups_to_keep
    }

    #[must_use]
    pub(crate) fn reverse_proxies(&self) -> Vec<review_web::archive::Config> {
        self.reverse_proxies.clone()
    }
}

pub fn backup_initial(time: NaiveTime, duration: Duration) -> Result<Duration> {
    use chrono::Utc;
    let now = Utc::now();
    let schedule = now.date_naive().and_time(time) - now.date_naive().and_time(now.time());

    if schedule.num_seconds() > 0 {
        Ok(schedule.to_std()?)
    } else {
        Ok((schedule + chrono::Duration::from_std(duration)?).to_std()?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load_config(parse().as_deref())?;
    let _guard = init_tracing(config.log_dir());

    match run(config).await {
        Ok(web_srv_shutdown_handle) => {
            if let Err(e) = shutdown().await {
                error!("Signal handling failed: {}", e);
            }
            web_srv_shutdown_handle.notify_one();
            web_srv_shutdown_handle.notified().await;
            info!("exit");
            Ok(())
        }
        Err(e) => {
            error!("An error occurred while starting REview: {:#}", e);
            std::process::exit(1);
        }
    }
}

async fn run(config: Config) -> Result<Arc<Notify>> {
    migrate_data_dir(config.data_dir(), config.backup_dir()).context("migration failed")?;

    let cert_manager: Arc<dyn CertManager> = Arc::new(MiniCertManager::new(
        config.cert.clone(),
        config.key.clone(),
    ));
    let ip_locator = if let Some(path) = config.ip2location() {
        Some(Arc::new(Mutex::new(
            ip2location::DB::from_file(path)
                .map_err(|e| anyhow!("cannot read IP location database: {:#?}", e))?,
        )))
    } else {
        None
    };
    let db = Database::new(config.database_url(), &config.ca_certs())
        .await
        .context("failed to connect to the PostgreSQL database")?;
    let store = {
        let store = Store::new(config.data_dir(), config.backup_dir())
            .map(Arc::new)
            .context("failed to connect to database")?;
        store
    };
    let agent_manager = Manager {};
    let cert_reload_handle = Arc::new(Notify::new());
    let web_config = web::ServerConfig {
        addr: config.graphql_srv_addr(),
        document_root: config.htdocs_dir().to_owned(),
        cert_manager,
        cert_reload_handle,
        ca_certs: config
            .ca_certs()
            .into_iter()
            .map(Path::to_path_buf)
            .collect(),
        reverse_proxies: config.reverse_proxies(),
    };

    let backup_cfg = BackupConfig::builder()
        .backup_path(config.backup_dir())
        .container(config.database_container())
        .num_of_backup(config.num_of_backups_to_keep())
        .database_dir(config.database_dir())?
        .database_url(config.database_url())?
        .build();
    let backup_cfg = Arc::new(RwLock::new(backup_cfg));
    let (sender, mut receiver) = mpsc::channel::<(Duration, Duration)>(1);
    info!("init backup schedule:{:?}", config.backup_schedule);
    tokio::spawn(async move {
        while let Some((init, duration)) = receiver.recv().await {
            info!("change backup schedule:{init:?}/{duration:?}");
        }
    });
    let web_srv_shutdown_handle = web::serve(
        web_config,
        db,
        store,
        ip_locator,
        agent_manager,
        backup_cfg,
        config.cfg_path,
        sender,
    )
    .await;

    Ok(web_srv_shutdown_handle)
}

fn parse() -> Option<String> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        return None;
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{} {}", package(), version());
        println!();
        println!(
            "USAGE: \
            \n    {} [CONFIG] \
            \n \
            \nFLAGS: \
            \n    -h, --help       Prints help information \
            \n    -V, --version    Prints version information \
            \n \
            \nARG: \
            \n    <CONFIG>    A TOML config file",
            package()
        );
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }

    Some(args[1].clone())
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn package() -> &'static str {
    env!("CARGO_PKG_NAME")
}

async fn shutdown() -> Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let terminate = terminate.recv();

    let mut interrupt = signal(SignalKind::interrupt())?;
    let interrupt = interrupt.recv();

    pin_mut!(terminate, interrupt);

    match future::select(terminate, interrupt).await {
        Either::Left(_) => info!("SIGTERM received"),
        Either::Right(_) => info!("SIGINT received"),
    }

    Ok(())
}

fn init_tracing(path: &Path) -> Result<WorkerGuard> {
    if !path.exists() {
        tracing_subscriber::fmt::init();
        bail!("Path not found {path:?}");
    }
    let file_name = format!("{}.log", env!("CARGO_PKG_NAME"));
    if fs::File::create(path.join(&file_name)).is_err() {
        tracing_subscriber::fmt::init();
        bail!("Cannot create file. {}/{file_name}", path.display());
    }
    let file_appender = tracing_appender::rolling::never(path, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let layer_file = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()));
    let layer_stdout = fmt::Layer::default()
        .with_ansi(true)
        .with_filter(EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(layer_file)
        .with(layer_stdout)
        .init();
    Ok(guard)
}
