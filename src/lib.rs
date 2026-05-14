use std::{ env::args, net::SocketAddr, sync::Arc, time::Instant };

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{ HeaderValue, Method, header::{ AUTHORIZATION, CONTENT_TYPE } },
    middleware,
};
use axum_server::tls_rustls::RustlsConfig;
use tower_http::cors::CorsLayer;
use crate::{
    database::Database,
    middlewares::track,
    routes::ily,
    utils::{ jwt::Jwt, turnstile::Turnstile },
    workers::{ WorkerSpec, Workers, WorkersAllocate },
};

pub mod database;
pub mod workers;
mod routes;
pub mod middlewares;
pub mod base;
pub mod utils;
pub mod consts;

pub struct AppState {
    pub worker: Workers,
    pub db: Database,
    pub jwt: Jwt,
    pub turnstile: Turnstile,
    pub debug: bool,
}

/// Must be called first for any interaction with the router.
pub fn init() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt().init();

    rustls::crypto::ring::default_provider().install_default().unwrap();
}

/// The core setup, this is what `main.rs` should call.
pub async fn core() {
    let host = std::env
        ::var("HOST")
        .expect("HOST must be set in .env file")
        .parse::<SocketAddr>()
        .unwrap();

    tracing::info!("Hello, world (world here is {})! :3", host);

    let mode: Vec<String> = args().collect();
    if mode.len() != 2 {
        tracing::error!("No required arguments provided. [secure/insecure]");
        return;
    }

    match mode[1].as_str() {
        "secure" => {
            tracing::info!("Serving in secure context...");
            let tls_config = RustlsConfig::from_pem_file(
                "cf-ocert.pem",
                "cf-okey.pem"
            ).await.unwrap();
            axum_server
                ::bind_rustls(host, tls_config)
                .serve(app(false).await.into_make_service()).await
                .unwrap();
        }
        "insecure" => {
            tracing::info!("Serving in insecure context...");
            tracing::warn!(
                "Insecure context is for local development only, do not fuck this up, plwease QwQ"
            );
            tracing::info!(
                "Disabled security features:\n- mSSL to communicate with Cloudflare.\n- Turnstile check."
            );
            axum_server::bind(host).serve(app(true).await.into_make_service()).await.unwrap();
        }
        _ => tracing::error!("No context chosen, shutting down... [secure/insecure]"),
    }
}

/// Creates an app.
pub async fn app(debug: bool) -> Router {
    tracing::info!("Initializing server state...");
    let boot_time = Instant::now();

    let app_state = Arc::new(AppState {
        worker: Workers::new(WorkersAllocate {
            hash_pass: WorkerSpec {
                threads: 12,
                buffer: 2048,
            },
            verify_pass: WorkerSpec {
                threads: 12,
                buffer: 2048,
            },
            verify_email: WorkerSpec {
                threads: 1,
                buffer: 100,
            },
        }),
        db: Database::default().await.unwrap(),
        jwt: utils::jwt::Jwt::new(),
        turnstile: Turnstile::default(),
        debug,
    });

    let cors = CorsLayer::new()
        .allow_origin(
            tower_http::cors::AllowOrigin::predicate(|origin: &HeaderValue, _| {
                let origin = origin.as_bytes();
                origin == b"https://koii.space" ||
                    (origin.starts_with(b"https://") && origin.ends_with(b".koii.space"))
            })
        )
        .allow_methods(vec![Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_credentials(true);

    tracing::info!(
        "Server started succesfully. (Boot time: {}ms)",
        boot_time.elapsed().as_millis()
    );

    Router::new()
        .nest("/account", routes::account::routes(app_state.clone()))
        .route("/ily", axum::routing::get(ily::handler))
        .layer(middleware::from_fn(track::log_requests))
        .layer(DefaultBodyLimit::max(1 * 1024 * 1024))
        .layer(cors)
}
