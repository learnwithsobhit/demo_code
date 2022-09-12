use common::config::config_service_server::ConfigServiceServer;
use common::config::{config_service_server::ConfigService, GetConfigRequest, GetConfigResponse};
use common::errors::Error;
use common::utils::{log_req, log_resp};
use log::*;
use serde::{Deserialize, Serialize};

/// Default HTTP2 keep-alive interval - sent every 30 seconds
/// Passed to: https://docs.rs/tonic/0.6.1/tonic/transport/channel/struct.Endpoint.html#method.http2_keep_alive_interval
pub const DEFAULT_GRPC_KEEP_ALIVE_SECONDS: u64 = 30;

/// Default HTTP2 keep-alive timeout - keep-alive fail if not received within this interval
/// Passed to: https://docs.rs/tonic/0.6.1/tonic/transport/channel/struct.Endpoint.html#method.keep_alive_timeout
pub const DEFAULT_GRPC_KEEP_ALIVE_TIMEOUT_SECONDS: u64 = 10;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatabaseConfig {
    /// Database ip or hostname
    pub ip: String,
    /// Port
    pub port: u16,
    /// User
    pub user: String,
    /// Password
    pub password: String,
    /// Schema
    pub db_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    /// Unique identifier for the server (node) instance. Should be persistent between restarts.
    /// If not set, the MAC address of the first network interface will be used
    pub node_id: Option<String>,
    /// The address that gRPC endpoints should listen on, for example 0.0.0.0:9876
    pub grpc_listen: String,
    /// The HTTP address that the server should listen on. Only used for version endpoint
    /// If not set, `0.0.0.0:port` is used, where `port` is equal to the `grpc_listen` port + 1
    pub http_listen: Option<String>,
    /// JWT secret. Used for validation of client requests
    pub jwt_secret: String,
    /// Number of async runtime threads. If not set, a value equal to the number of logical CPU cores
    /// is used (via num_cpus Rust crate)
    pub runtime_threads: Option<usize>,

    /// HTTP2 gRPC keep-alive interval. If not set, defaults to 30 seconds
    /// Value is passed to: https://docs.rs/tonic/0.6.1/tonic/transport/channel/struct.Endpoint.html#method.http2_keep_alive_interval
    pub grpc_keep_alive_interval_sec: Option<u64>,
    /// HTTP gRPC keep-alive timeout. If not set, defaults to 10 seconds
    /// Value is passed to: https://docs.rs/tonic/0.6.1/tonic/transport/channel/struct.Endpoint.html#method.keep_alive_timeout
    pub grpc_keep_alive_timeout_sec: Option<u64>,

    /// Cloudflare Stream account ID
    pub cloudflare_stream_acct_id: String,
    /// Cloudflare Stream account key
    pub cloudflare_stream_key: String,

    /// Config database cfg
    pub db: DatabaseConfig,

    /// Files server gRPC address
    pub files_server_address: String,
    /// Maximum simultaneous flie server connections. If not set defaults to 1000.
    pub max_file_srv_connections: Option<usize>,
    /// Files server gRPC address seen flom the client network
    pub files_server_address_ext: String,
}

impl ServerConfig {
    ///
    /// Validate the server configuration. Returns a String describing the error if the config is invalid
    ///
    pub fn validate(&self) -> Result<(), String> {
        if self.grpc_listen.is_empty() {
            return Err("grpc_listen configuration is empty (not set)".to_string());
        }

        if self.jwt_secret.is_empty() {
            return Err("jwt_secret configuration is empty (not set)".to_string());
        }

        if let Some(threads) = self.runtime_threads {
            if threads < 2 {
                return Err(format!(
                    "Invalid number of runtime threads: {} - threads must be at least 2",
                    threads
                ));
            }
        }

        if self.files_server_address.is_empty() {
            return Err("files_server_address configuration is empty (not set)".to_string());
        }

        if self.files_server_address_ext.is_empty() {
            return Err("files_server_address_ext configuration is empty (not set)".to_string());
        }

        Ok(())
    }

    pub fn node_id(&mut self) -> String {
        if let Some(s) = &self.node_id {
            s.clone()
        } else {
            let r = mac_address::get_mac_address();
            if let Ok(Some(ma)) = r {
                let n = ma.to_string();
                self.node_id = Some(n.clone());
                n
            } else {
                error!(
                    "Node ID was not provided and failed to get MAC address: {:?}",
                    r
                );
                panic!("Node ID not provided and could not generate node ID from MAC address");
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BootstrapConfig {
    /// Platform admin username
    pub username: String,
    /// Platform admin password
    pub password: String,
    /// Path to database setup script file
    pub setup_script: String,
}

pub struct ConfigEndpoints {
    file_service_address: String,
}

impl ConfigEndpoints {
    pub fn create(cfg: &ServerConfig) -> Result<ConfigServiceServer<Self>, Error> {
        Ok(ConfigServiceServer::new(ConfigEndpoints {
            file_service_address: cfg.files_server_address_ext.clone(),
        }))
    }
}

#[tonic::async_trait]
impl ConfigService for ConfigEndpoints {
    ///
    /// Grpc server implementation for get config endpoint
    ///
    async fn get_config(
        &self,
        req: tonic::Request<GetConfigRequest>,
    ) -> Result<tonic::Response<GetConfigResponse>, tonic::Status> {
        let (endpoint, start) = log_req("ConfigService::get_config", &req);

        let response = tonic::Response::new(GetConfigResponse {
            file_server_addr: self.file_service_address.clone(),
        });

        log_resp(endpoint, &req, &start, 0);

        Ok(response)
    }
}
