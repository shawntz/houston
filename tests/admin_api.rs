use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use std::sync::Mutex;
use houston::config::AppConfig;
use houston::db;
use houston::auth::{password, session};
use houston::db::{users, sessions, apps, assignments};

fn build_state(conn: rusqlite::Connection) -> Arc<houston::server::AppState> {
    let config = AppConfig::default();
    let kp = houston::crypto::keys::generate_ed25519_keypair().unwrap();
    let csrf_key = vec![0u8; 32];
    let rp_origin = url::Url::parse("https://localhost").unwrap();
    let webauthn = houston::auth::webauthn::build_webauthn("localhost", &rp_origin);
    let rsa = houston::crypto::keys::generate_rsa_keypair_and_cert("https://localhost").unwrap();

    Arc::new(houston::server::AppState {
        config,
        db: Mutex::new(conn),
        ed25519_keypair: kp,
        rsa_private_key_der: rsa.private_key_der,
        x509_cert_der: rsa.x509_cert_der,
        login_rate_limiter: houston::middleware::rate_limit::RateLimiter::new(10, 60),
        csrf_key,
        webauthn,
        webauthn_state: houston::auth::webauthn::WebauthnState::new(),
        pending_saml: std::sync::Mutex::new(std::collections::HashMap::new()),
    })
}

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

    let state = build_state(conn);
    let cookie_name = state.config.session.cookie_name.clone();

    let cookie = format!("{cookie_name}={token}");
    let app = houston::server::build_router(state);
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

#[tokio::test]
async fn test_app_drawer_requires_auth() {
    let (app, _) = test_state();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect to /login
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

#[tokio::test]
async fn test_app_drawer_shows_apps() {
    let conn = db::test_db();

    let pw_hash = password::hash_password("password").unwrap();
    let user = users::create_user(&conn, &users::CreateUser {
        username: "alice".into(),
        email: "alice@test.com".into(),
        display_name: "Alice".into(),
        password_hash: pw_hash,
        is_admin: false,
    }).unwrap();

    let token = session::generate_session_token();
    let token_hash = session::hash_token(&token);
    sessions::create_session(&conn, &user.id, &token_hash, "127.0.0.1", "test", 3600).unwrap();

    // Create and assign apps
    let oidc_app = apps::create_app(&conn, &apps::CreateApp::Oidc {
        name: "My OIDC App".into(),
        redirect_uris: vec![],
    }).unwrap();
    let bookmark_app = apps::create_app(&conn, &apps::CreateApp::Bookmark {
        name: "My Bookmark".into(),
        url: "https://example.com".into(),
    }).unwrap();
    assignments::assign_user_to_app(&conn, &user.id, &oidc_app.id).unwrap();
    assignments::assign_user_to_app(&conn, &user.id, &bookmark_app.id).unwrap();

    let state = build_state(conn);
    let cookie_name = state.config.session.cookie_name.clone();
    let cookie = format!("{cookie_name}={token}");
    let app = houston::server::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("My OIDC App"));
    assert!(html.contains("My Bookmark"));
    assert!(html.contains("https://example.com"));
    // Non-admin user should not see admin link
    assert!(!html.contains("Admin Dashboard"));
}
