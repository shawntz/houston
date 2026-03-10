use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use std::sync::Mutex;
use minikta::config::AppConfig;
use minikta::db;
use minikta::auth::{password, session};
use minikta::db::{users, sessions};

fn test_state() -> (axum::Router, String) {
    let conn = db::test_db();

    let pw_hash = password::hash_password("admin_password").unwrap();
    let admin = users::create_user(&conn, &users::CreateUser {
        username: "admin".into(),
        email: "admin@test.com".into(),
        display_name: "Admin".into(),
        password_hash: pw_hash,
        is_admin: true,
    }).unwrap();

    let token = session::generate_session_token();
    let token_hash = session::hash_token(&token);
    sessions::create_session(&conn, &admin.id, &token_hash, "127.0.0.1", "test", 3600).unwrap();

    let config = AppConfig::default();
    let cookie_name = config.session.cookie_name.clone();
    let kp = minikta::crypto::keys::generate_ed25519_keypair().unwrap();
    let csrf_key = vec![0u8; 32];
    let rp_origin = url::Url::parse("https://localhost").unwrap();
    let webauthn = minikta::auth::webauthn::build_webauthn("localhost", &rp_origin);

    let state = Arc::new(minikta::server::AppState {
        config,
        db: Mutex::new(conn),
        ed25519_keypair: kp,
        login_rate_limiter: minikta::middleware::rate_limit::RateLimiter::new(10, 60),
        csrf_key,
        webauthn,
        webauthn_state: minikta::auth::webauthn::WebauthnState::new(),
    });

    let cookie = format!("{cookie_name}={token}");
    let app = minikta::server::build_router(state);
    (app, cookie)
}

#[tokio::test]
async fn test_admin_list_users() {
    let (app, cookie) = test_state();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/users")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let users: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["username"], "admin");
    assert!(users[0].get("password_hash").is_none());
}

#[tokio::test]
async fn test_admin_create_user() {
    let (app, cookie) = test_state();

    let body = serde_json::json!({
        "username": "newuser",
        "email": "new@test.com",
        "display_name": "New User",
        "password": "strongpassword123",
        "is_admin": false,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/users")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let user: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(user["username"], "newuser");
    assert_eq!(user["is_admin"], false);
}

#[tokio::test]
async fn test_admin_unauthorized_without_session() {
    let (app, _) = test_state();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_list_apps() {
    let (app, cookie) = test_state();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/apps")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let apps: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(apps.is_empty());
}

#[tokio::test]
async fn test_admin_create_oidc_app() {
    let (app, cookie) = test_state();

    let body = serde_json::json!({
        "name": "Test OIDC App",
        "protocol": "oidc",
        "redirect_uris": ["https://app.test/callback"],
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/apps")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created_app: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created_app["name"], "Test OIDC App");
    assert_eq!(created_app["protocol"], "oidc");
    assert!(created_app["client_id"].as_str().is_some());
}
