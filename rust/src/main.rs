//! Dual-mode entrypoint: Lambda or local dev server.
//!
//! Detects Lambda runtime via `AWS_LAMBDA_RUNTIME_API` env var.
//! - Lambda: `lambda_http::run(app)` — API Gateway v2 → HTTP
//! - Local: `axum::serve(listener, app)` — standard TCP server

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

use l42_token_handler::cedar::engine::CedarState;
use l42_token_handler::cognito::jwt::JwksCache;
use l42_token_handler::config::Config;
use l42_token_handler::session::memory::InMemoryBackend;
use l42_token_handler::session::middleware::SessionLayer;
use l42_token_handler::session::AnyBackend;
use l42_token_handler::{create_app, AppState};

#[tokio::main]
async fn main() {
    let is_lambda = env::var("AWS_LAMBDA_RUNTIME_API").is_ok();

    // Init tracing: JSON for Lambda, pretty for local
    if is_lambda {
        fmt()
            .json()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    } else {
        // Load .env for local dev
        let _ = dotenvy::dotenv();
        fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    let config = Config::from_env().expect("Failed to load configuration");
    let http_client = reqwest::Client::new();
    let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

    // Init Cedar (fail-closed: if init fails, /auth/authorize returns 503)
    let cedar = {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let cedar_dir = PathBuf::from(&manifest_dir).join("cedar");
        let schema_path = cedar_dir.join("schema.cedarschema.json");
        let policy_dir = cedar_dir.join("policies");

        if schema_path.exists() && policy_dir.exists() {
            match CedarState::init(&schema_path, &policy_dir) {
                Ok(state) => {
                    tracing::info!("Cedar engine initialized with schema + policies");
                    Some(state)
                }
                Err(e) => {
                    tracing::error!("Cedar init failed (running without authorization): {}", e);
                    None
                }
            }
        } else {
            tracing::warn!(
                "Cedar schema/policies not found at {} — running without authorization",
                cedar_dir.display()
            );
            None
        }
    };

    // Session backend: DynamoDB for production, InMemory for dev
    let session_backend: AnyBackend = if config.session_backend == "dynamodb" {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let dynamo_client = if config.dynamodb_endpoint.is_empty() {
            aws_sdk_dynamodb::Client::new(&sdk_config)
        } else {
            let dynamo_config = aws_sdk_dynamodb::config::Builder::from(&sdk_config)
                .endpoint_url(&config.dynamodb_endpoint)
                .build();
            aws_sdk_dynamodb::Client::from_conf(dynamo_config)
        };
        tracing::info!(
            "Using DynamoDB session backend (table: {})",
            config.dynamodb_table
        );
        AnyBackend::DynamoDb(l42_token_handler::session::dynamodb::DynamoDbBackend::new(
            dynamo_client,
            config.dynamodb_table.clone(),
        ))
    } else {
        tracing::info!("Using in-memory session backend");
        AnyBackend::Memory(InMemoryBackend::new())
    };

    let session_layer = Arc::new(SessionLayer {
        backend: Arc::new(session_backend),
        secret: config.session_secret.clone(),
        https_only: config.session_https_only,
    });

    let state = Arc::new(AppState {
        config: config.clone(),
        http_client,
        jwks_cache,
        cedar,
        session_layer,
    });

    let app = create_app(state);

    if is_lambda {
        tracing::info!("Starting in Lambda mode");
        lambda_http::run(app).await.expect("Lambda runtime error");
    } else {
        let addr = format!("0.0.0.0:{}", config.port);
        tracing::info!("Starting local server on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("Failed to bind");
        axum::serve(listener, app).await.expect("Server error");
    }
}
