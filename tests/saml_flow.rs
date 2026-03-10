use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use std::sync::Mutex;
use houston::config::AppConfig;
use houston::db;

fn test_router() -> axum::Router {
    let conn = db::test_db();
    let config = AppConfig::default();
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

    houston::server::build_router(state)
}

#[tokio::test]
async fn test_saml_metadata() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/saml/metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
    assert_eq!(content_type, "application/xml");

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let xml = String::from_utf8(body.to_vec()).unwrap();
    assert!(xml.contains("EntityDescriptor"));
    assert!(xml.contains("SingleSignOnService"));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"));
}

#[tokio::test]
async fn test_saml_sso_requires_saml_request() {
    let app = test_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/saml/sso")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Missing SAMLRequest"));
}
