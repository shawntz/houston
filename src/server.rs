use std::collections::HashMap;
use std::sync::Arc;
use axum::Router;
use rusqlite::Connection;
use std::sync::Mutex;

use ring::signature::KeyPair;

use crate::auth::webauthn::WebauthnState;
use crate::config::AppConfig;
use crate::crypto::keys::Ed25519Keypair;
use crate::middleware::rate_limit::RateLimiter;

pub struct PendingSamlRequest {
    pub saml_request: String,
    pub relay_state: Option<String>,
    pub created_at: std::time::Instant,
}

pub struct AppState {
    pub config: AppConfig,
    pub db: Mutex<Connection>,
    pub ed25519_keypair: Ed25519Keypair,
    pub rsa_private_key_der: Vec<u8>,
    pub x509_cert_der: Vec<u8>,
    pub login_rate_limiter: RateLimiter,
    pub csrf_key: Vec<u8>,
    pub webauthn: webauthn_rs::prelude::Webauthn,
    pub webauthn_state: WebauthnState,
    pub pending_saml: Mutex<HashMap<String, PendingSamlRequest>>,
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
                .unwrap_or_else(|_| "houston=info,tower_http=info".into())
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

    // Load or generate RSA key + X509 cert for SAML signing
    let rsa_key_path = format!("{keys_dir}/rsa.key.enc");
    let rsa_cert_path = format!("{keys_dir}/rsa.cert.der");

    let (rsa_private_key_der, x509_cert_der) = if std::path::Path::new(&rsa_key_path).exists() {
        tracing::info!("Loading existing RSA signing key");
        let private_key = crate::crypto::keys::load_encrypted_key(&rsa_key_path, &config.secrets.master_secret)?;
        let cert = std::fs::read(&rsa_cert_path)?;
        (private_key, cert)
    } else {
        tracing::info!("Generating new RSA signing key and X509 certificate");
        let rsa = crate::crypto::keys::generate_rsa_keypair_and_cert(&config.server.external_url)?;
        crate::crypto::keys::save_encrypted_key(&rsa.private_key_der, &rsa_key_path, &config.secrets.master_secret)?;
        std::fs::write(&rsa_cert_path, &rsa.x509_cert_der)?;
        (rsa.private_key_der, rsa.x509_cert_der)
    };

    let csrf_key = crate::crypto::hkdf::derive_key(&config.secrets.master_secret, "csrf-tokens", 32)?;

    let login_rate_limiter = RateLimiter::new(
        config.rate_limit.login_max_attempts,
        config.rate_limit.login_window_seconds,
    );

    // Initialize WebAuthn
    let rp_origin = url::Url::parse(&config.server.external_url)
        .expect("external_url must be a valid URL");
    let rp_id = rp_origin.domain().unwrap_or("localhost").to_string();
    let webauthn = crate::auth::webauthn::build_webauthn(&rp_id, &rp_origin);
    let webauthn_state = WebauthnState::new();

    let state = Arc::new(AppState {
        config: config.clone(),
        db: Mutex::new(conn),
        ed25519_keypair,
        rsa_private_key_der,
        x509_cert_der,
        login_rate_limiter,
        csrf_key,
        webauthn,
        webauthn_state,
        pending_saml: Mutex::new(HashMap::new()),
    });

    let app = build_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("houston listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
