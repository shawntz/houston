use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use std::sync::Mutex;
use houston::config::AppConfig;
use houston::db;
use houston::auth::{password, session};
use houston::db::{users, sessions, apps};

fn test_state_with_app() -> (axum::Router, String, String) {
    let conn = db::test_db();

    let pw_hash = password::hash_password("password123").unwrap();
    let user = users::create_user(&conn, &users::CreateUser {
        username: "oidcuser".into(),
        email: "oidc@test.com".into(),
        display_name: "OIDC User".into(),
        password_hash: pw_hash,
        is_admin: false,
    }).unwrap();

    let token = session::generate_session_token();
    let token_hash = session::hash_token(&token);
    sessions::create_session(&conn, &user.id, &token_hash, "127.0.0.1", "test", 3600).unwrap();

    let app = apps::create_app(&conn, &apps::CreateApp::Oidc {
        name: "Test App".into(),
        redirect_uris: vec!["https://app.test/callback".into()],
    }).unwrap();
    let client_id = app.client_id.clone().unwrap();

    let config = AppConfig::default();
    let cookie_name = config.session.cookie_name.clone();
    let kp = houston::crypto::keys::generate_ed25519_keypair().unwrap();
    let csrf_key = vec![0u8; 32];
    let rp_origin = url::Url::parse("https://localhost").unwrap();
    let webauthn = houston::auth::webauthn::build_webauthn("localhost", &rp_origin);

    let state = Arc::new(houston::server::AppState {
        config,
        db: Mutex::new(conn),
        ed25519_keypair: kp,
        login_rate_limiter: houston::middleware::rate_limit::RateLimiter::new(10, 60),
        csrf_key,
        webauthn,
        webauthn_state: houston::auth::webauthn::WebauthnState::new(),
    });

    let cookie = format!("{cookie_name}={token}");
    let router = houston::server::build_router(state);
    (router, client_id, cookie)
}

#[tokio::test]
async fn test_oidc_discovery() {
    let (app, _, _) = test_state_with_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(doc["issuer"].as_str().is_some());
    assert!(doc["authorization_endpoint"].as_str().is_some());
    assert!(doc["token_endpoint"].as_str().is_some());
}

#[tokio::test]
async fn test_oidc_jwks() {
    let (app, _, _) = test_state_with_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!jwks["keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_oidc_authorize_requires_session() {
    let (app, client_id, _) = test_state_with_app();

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256",
        client_id,
        urlencoding::encode("https://app.test/callback")
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("/login"));
}

#[tokio::test]
async fn test_oidc_authorize_with_session_returns_code() {
    let (app, client_id, cookie) = test_state_with_app();

    use base64::Engine;
    use ring::digest;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let hash = digest::digest(&digest::SHA256, verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref());

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=xyz&code_challenge={}&code_challenge_method=S256",
        client_id,
        urlencoding::encode("https://app.test/callback"),
        challenge,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://app.test/callback?code="));
    assert!(location.contains("state=xyz"));
}
