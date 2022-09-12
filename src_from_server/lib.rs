use common::client_pool::SimpleInterceptor;
use common::errors::Error;
use common::files::files_service_client::FilesServiceClient;

use crate::admin::AdminEndpoints;
use crate::app::AppEndpoints;
use crate::config::{BootstrapConfig, ConfigEndpoints, ServerConfig};
use crate::config::{DEFAULT_GRPC_KEEP_ALIVE_SECONDS, DEFAULT_GRPC_KEEP_ALIVE_TIMEOUT_SECONDS};
use crate::content::ContentEndpoints;
use crate::database::Database;
use crate::integrations::cloudflare_manager::CloudflareStreamManager;
use crate::rooms::RoomsEndpoints;
use crate::user::UserEndpoints;

use futures::future::{AbortHandle, Abortable};
use futures::FutureExt;
use log::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Server as TonicServer};

pub mod actix;
pub mod admin;
pub mod app;
pub mod config;
pub mod content;
pub mod database;
pub mod integrations;
// pub mod metrics;
pub mod rooms;
pub mod user;
pub mod utils;

// For Built tool, that gives us version and commit hash at runtime
include!(concat!(env!("OUT_DIR"), "/built.rs"));

/// Repository release version
pub const RELEASE_VERSION: &str = include_str!("../../VERSION");

pub struct Server {
    pub config: ServerConfig,
    pub grpc_server: JoinHandle<Result<(), futures::future::Aborted>>,
    /// Handle for shutting down gRPC (Tonic) server
    #[allow(dead_code)]
    pub shutdown_handle: mpsc::UnboundedSender<()>,
    #[allow(dead_code)]
    grpc_abort_handle: AbortHandle,
    #[allow(dead_code)]
    pub http_server: JoinHandle<Result<Result<(), std::io::Error>, futures::future::Aborted>>,
    #[allow(dead_code)]
    http_abort_handle: AbortHandle,
    pub db: Arc<Database>,
    pub cloudflare_mgr: Arc<CloudflareStreamManager>,
}

impl Server {
    pub async fn init(
        mut config: ServerConfig,
        boot_cfg: Option<BootstrapConfig>,
        integration_tests: bool,
    ) -> Result<Server, Error> {
        info!("Initializing the server");
        if let Some(b) = boot_cfg {
            info!("Bootstrapping the database");
            Database::init_db(&config.db, b).await?;
        }

        let listen = config.grpc_listen.parse().unwrap();

        // One-shot channel used for shutdown
        let (tx, rx) = mpsc::unbounded_channel();

        let http2_keepalive = config
            .grpc_keep_alive_interval_sec
            .unwrap_or(DEFAULT_GRPC_KEEP_ALIVE_SECONDS);
        let http2_keepalive_timeout = config
            .grpc_keep_alive_timeout_sec
            .unwrap_or(DEFAULT_GRPC_KEEP_ALIVE_TIMEOUT_SECONDS);

        let db = Arc::new(
            Database::connect(&config.db)
                .await
                .expect("Failed to connect to database"),
        );

        let cloudflare_mgr = Arc::new(
            CloudflareStreamManager::new(config.node_id().clone(), db.clone(), &config).await?,
        );

        let pool = Arc::new(common::client_pool::Pool::new(
            &config.jwt_secret,
            config.files_server_address.clone(),
            config.max_file_srv_connections,
            Box::new(|c: Channel, i: SimpleInterceptor| FilesServiceClient::with_interceptor(c, i)),
        ));
        let config_svc =
            ConfigEndpoints::create(&config).expect("Failed to create config endpoints");
        let admin_svc = AdminEndpoints::create(db.clone(), &config, pool.clone())
            .expect("Failed to create admin endpoints");
        let app_svc =
            AppEndpoints::create(db.clone(), &config).expect("Failed to create app endpoints");
        let room_svc =
            RoomsEndpoints::create(db.clone(), &config).expect("Failed to create room endpoints");
        let user_svc = UserEndpoints::create(
            db.clone(),
            &config.jwt_secret,
            integration_tests,
            pool.clone(),
        )
        .expect("Failed to create user endpoints");
        let content_svc = ContentEndpoints::create(
            config.node_id(),
            db.clone(),
            &config,
            &config.cloudflare_stream_acct_id,
            &config.cloudflare_stream_key,
            cloudflare_mgr.clone(),
            pool,
        )
        .expect("Failed to create content endpoints");

        let future = async move {
            let mut shutdown_rx_handle = rx;
            TonicServer::builder()
                .http2_keepalive_interval(Some(Duration::from_secs(http2_keepalive)))
                .http2_keepalive_timeout(Some(Duration::from_secs(http2_keepalive_timeout)))
                .add_service(config_svc)
                .add_service(admin_svc)
                .add_service(user_svc)
                .add_service(content_svc)
                .add_service(app_svc)
                .add_service(room_svc)
                .serve_with_shutdown(listen, shutdown_rx_handle.recv().map(drop))
                .await
                .unwrap()
        };

        let (grpc_handle, reg) = AbortHandle::new_pair();
        let f = Abortable::new(future, reg);
        let server = tokio::spawn(f);

        let (http_handle, reg) = AbortHandle::new_pair();
        let f = Abortable::new(
            actix::start_actix_server(
                config
                    .http_listen
                    .clone()
                    .unwrap_or_else(|| actix::default_http_address(&config.grpc_listen)),
            ),
            reg,
        );
        let http_server = tokio::spawn(f);

        info!("Platform gRPC server listening on: {}", config.grpc_listen);

        Ok(Server {
            grpc_server: server,
            config,
            shutdown_handle: tx,
            grpc_abort_handle: grpc_handle,
            http_server,
            http_abort_handle: http_handle,
            db,
            cloudflare_mgr,
        })
    }
}
