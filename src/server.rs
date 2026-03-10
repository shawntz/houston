use std::sync::Arc;
use axum::Router;
use rusqlite::Connection;
use std::sync::Mutex;

use ring::signature::KeyPair;

use crate::config::AppConfig;
use crate::crypto::keys::Ed25519Keypair;
use crate::middleware::rate_limit::RateLimiter;

pub struct AppState {
    pub config: AppConfig,
    pub db: Mutex<Connection>,
    pub ed25519_keypair: Ed25519Keypair,
    pub login_rate_limiter: RateLimiter,
    pub csrf_key: Vec<u8>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(crate::web::routes(state.clone()))
        .merge(crate::oidc::routes())
        .merge(crate::saml::routes())
        .merge(crate::admin::routes())
        .with_state(state)
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "minikta=info,tower_http=info".into())
        )
        .init();

    tracing::info!("Initializing database at {}", config.database.path);
    let conn = crate::db::initialize(&config.database.path)?;

    // Load or generate signing keys
    let keys_dir = "keys";
    std::fs::create_dir_all(keys_dir)?;
    let ed25519_key_path = format!("{keys_dir}/ed25519.key.enc");

    let ed25519_keypair = if std::path::Path::new(&ed25519_key_path).exists() {
        tracing::info!("Loading existing Ed25519 signing key");
        let private_key = crate::crypto::keys::load_encrypted_key(&ed25519_key_path, &config.secrets.master_secret)?;
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| anyhow::anyhow!("failed to load Ed25519 keypair"))?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        let kid = std::fs::read_to_string(format!("{keys_dir}/ed25519.kid"))
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
        Ed25519Keypair { private_key_pkcs8: private_key, public_key_bytes: public_key, kid }
    } else {
        tracing::info!("Generating new Ed25519 signing key");
        let kp = crate::crypto::keys::generate_ed25519_keypair()?;
        crate::crypto::keys::save_encrypted_key(&kp.private_key_pkcs8, &ed25519_key_path, &config.secrets.master_secret)?;
        std::fs::write(format!("{keys_dir}/ed25519.kid"), &kp.kid)?;
        kp
    };

    let csrf_key = crate::crypto::hkdf::derive_key(&config.secrets.master_secret, "csrf-tokens", 32)?;

    let login_rate_limiter = RateLimiter::new(
        config.rate_limit.login_max_attempts,
        config.rate_limit.login_window_seconds,
    );

    let state = Arc::new(AppState {
        config: config.clone(),
        db: Mutex::new(conn),
        ed25519_keypair,
        login_rate_limiter,
        csrf_key,
    });

    let app = build_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("minikta listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
