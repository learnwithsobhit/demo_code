use actix_web::{
    get,
    web::{self, Data},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use log::*;

use crate::{GIT_COMMIT_HASH, RELEASE_VERSION};

///
/// Get the default HTTP listen address (and port), when a value is not provided in the configuration.
/// `0.0.0.0:port` is used, where `port` is equal to the `grpc_listen` port + 1
///
pub fn default_http_address(grpc_addr: &str) -> String {
    let split: Vec<&str> = grpc_addr.split(":").collect();
    if split.len() != 2 {
        error!(
            "Invalid gRPC listen addess: expected value like 0.0.0.0:12345, got: {}",
            grpc_addr
        );
        panic!("Invalid gRPC listen address");
    }

    let p: i16 = split.get(1).unwrap().parse().unwrap();
    format!("0.0.0.0:{}", p + 1)
}

///
/// Start the Actix-web server, listening on the specified address.
///
/// # Arguments
/// * `bind_addr`: The IP/address and port to listen on, such as `0.0.0.0:12345`
///
pub async fn start_actix_server(bind_addr: String) -> Result<(), std::io::Error> {
    let state = AppState {};

    let state2 = state.clone();

    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state2.clone()))
            .service(version)
    })
    .bind(&bind_addr)
    .expect(format!("Could not bind to address: {}", &bind_addr).as_str())
    // Set 2 worker threads. Don't need many, as we're only using it for metrics
    .workers(2)
    .run();

    info!("Platform HTTP server listening on {}", bind_addr);

    server.await
}

///
/// Internal HTTP app state
///
#[derive(Debug, Clone)]
pub struct AppState {}

///
/// Get the server version and commit hash
///
#[get("/version")]
pub async fn version(_r: HttpRequest, _state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().content_type("text/plain").body(format!(
        "{} {}",
        RELEASE_VERSION,
        GIT_COMMIT_HASH.unwrap_or("")
    ))
}
