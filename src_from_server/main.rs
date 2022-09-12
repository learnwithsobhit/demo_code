extern crate server;

use clap::{Arg, Command};
use log::*;
use server::config::{BootstrapConfig, ServerConfig};
use server::Server;
use std::path::Path;
use std::sync::Arc;

const ENV_CONFIG_DB_HOST: &str = "CONFIG_DB_HOST";

fn main() {
    let version = server::RELEASE_VERSION.trim().to_string();
    let hash = server::GIT_COMMIT_HASH.unwrap_or("");
    let version_str = version + " - " + hash;

    let matches = Command::new("Platform server")
        .version(version_str.as_str())
        .arg(
            Arg::new("config_path")
                .help("Path to the YAML configuration file")
                .short('c')
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("log_path")
                .help("Path to the logging YAML configuration file")
                .short('l')
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("bootstrap_cfg")
                .help("Path to the bootstrap YAML configuration file")
                .short('b')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::new("integration_tests")
                .help("Integration tests mode")
                .short('i')
                .takes_value(false)
                .required(false),
        )
        .get_matches();

    let path_str = matches.value_of("config_path").unwrap();
    let path = Path::new(path_str);
    if !path.exists() {
        panic!(
            "Provided configuration file path does not exist: {}",
            path_str
        );
    }

    let str = std::fs::read_to_string(path).expect("Failed to read configuration file");
    let mut config: ServerConfig =
        serde_yaml::from_str(str.as_str()).expect("Failed to deserialize configuration file");

    // Env variables take precedence
    if let Ok(host) = std::env::var(ENV_CONFIG_DB_HOST) {
        config.db.ip = host;
    }

    let logging_str = matches.value_of("log_path").unwrap();
    let log_path = Path::new(logging_str);
    if !log_path.exists() {
        panic!(
            "Provided logging configuration file path does not exist: {}",
            logging_str
        );
    }

    // Initialize logger
    log4rs::init_file(logging_str, Default::default()).unwrap();

    config
        .validate()
        .expect("Server configuration failed validation");

    let bootstrap = if let Some(p) = matches.value_of("bootstrap_cfg") {
        let str = std::fs::read_to_string(p).expect("Failed to read cootstrap configuration file");
        let config: BootstrapConfig =
            serde_yaml::from_str(&str).expect("Failed to deserialize bootstrap configuration file");
        Some(config)
    } else {
        None
    };

    let integration = matches.is_present("integration_tests");

    let grpc_listen = config.grpc_listen.clone();

    let threads = config.runtime_threads.unwrap_or_else(num_cpus::get);
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .max_blocking_threads(threads)
            .enable_all()
            .build()
            .unwrap(),
    );

    let server = rt
        .block_on(Server::init(config.clone(), bootstrap, integration))
        .expect("Failed to launch server");
    info!(
        "Platform server instance (version = {}) launched. gRPC listening on {}",
        version_str, grpc_listen
    );

    let mut tx_cpy = Some(server.shutdown_handle.clone());

    rt.block_on(async move {
        tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            if let Some(h) = tx_cpy.take() {
                let _ = h.send(());
            }
        },
        res = server.grpc_server => {
            if let Err(e) = res {
                info!("Platform grpc server error: {}", e);
            } else {
                info!("Platform grpc server stopped");
            }
        },
        res = server.http_server => {
            if let Err(e) = res {
                info!("Platform http server error: {}", e);
            } else {
                info!("Platform grpc server stopped");
            }
        },
        }
    });
}
