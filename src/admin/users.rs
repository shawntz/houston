use axum::{
    extract::{Path, State},
    response::{Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::auth::session;
use crate::db::{sessions, users};
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/users", get(list_users))
        .route("/api/admin/users", post(create_user))
        .route("/api/admin/users/{id}", get(get_user))
        .route("/api/admin/users/{id}", put(update_user))
        .route("/api/admin/users/{id}", delete(delete_user))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    display_name: String,
    password: String,
    is_admin: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    email: Option<String>,
    display_name: Option<String>,
    password: Option<String>,
    is_admin: Option<bool>,
}

pub fn require_admin_from_headers(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), Response> {
    let token = extract_session_token(headers, &state.config.session.cookie_name)
        .ok_or_else(|| error_response("unauthorized", 401))?;

    let token_hash = session::hash_token(&token);
    let db = state.db.lock().unwrap();
    let sess = sessions::get_valid_session_by_token_hash(&db, &token_hash)
        .ok()
        .flatten()
        .ok_or_else(|| error_response("unauthorized", 401))?;

    let user = users::get_user_by_id(&db, &sess.user_id)
        .ok()
        .flatten()
        .ok_or_else(|| error_response("unauthorized", 401))?;

    if !user.is_admin {
        return Err(error_response("forbidden", 403));
    }

    Ok(())
}

fn extract_session_token(headers: &axum::http::HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{cookie_name}=")))
                .map(|c| c.splitn(2, '=').nth(1).unwrap_or("").to_string())
        })
}

fn error_response(error: &str, status: u16) -> Response {
    let body = serde_json::json!({ "error": error });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match users::list_users(&db) {
        Ok(users) => {
            let sanitized: Vec<_> = users.into_iter().map(sanitize_user).collect();
            Json(sanitized).into_response()
        }
        Err(_) => error_response("internal_error", 500),
    }
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match users::get_user_by_id(&db, &id) {
        Ok(Some(user)) => Json(sanitize_user(user)).into_response(),
        Ok(None) => error_response("not_found", 404),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Response {
    if let Err(e) = require_admin_from_headers(&state, &headers) {
        return e;
    }

    let password_hash = match crate::auth::password::hash_password(&body.password) {
        Ok(h) => h,
        Err(_) => return error_response("failed to hash password", 500),
    };

    let create = users::CreateUser {
        username: body.username,
        email: body.email,
        display_name: body.display_name,
        password_hash,
        is_admin: body.is_admin.unwrap_or(false),
    };

    let db = state.db.lock().unwrap();
    match users::create_user(&db, &create) {
        Ok(user) => {
            let mut resp = Json(sanitize_user(user)).into_response();
            *resp.status_mut() = axum::http::StatusCode::CREATED;
            resp
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                error_response("username or email already exists", 409)
            } else {
                error_response("internal_error", 500)
            }
        }
    }
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateUserRequest>,
) -> Response {
    if let Err(e) = require_admin_from_headers(&state, &headers) {
        return e;
    }

    let password_hash = match &body.password {
        Some(pw) => match crate::auth::password::hash_password(pw) {
            Ok(h) => Some(h),
            Err(_) => return error_response("failed to hash password", 500),
        },
        None => None,
    };

    let updates = users::UpdateUser {
        email: body.email,
        display_name: body.display_name,
        password_hash,
        totp_secret: None,
        is_admin: body.is_admin,
    };

    let db = state.db.lock().unwrap();

    // Check user exists
    match users::get_user_by_id(&db, &id) {
        Ok(None) => return error_response("not_found", 404),
        Err(_) => return error_response("internal_error", 500),
        _ => {}
    }

    match users::update_user(&db, &id, &updates) {
        Ok(()) => {
            let user = users::get_user_by_id(&db, &id).ok().flatten().unwrap();
            Json(sanitize_user(user)).into_response()
        }
        Err(_) => error_response("internal_error", 500),
    }
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match users::get_user_by_id(&db, &id) {
        Ok(None) => return error_response("not_found", 404),
        Err(_) => return error_response("internal_error", 500),
        _ => {}
    }

    match users::delete_user(&db, &id) {
        Ok(()) => Response::builder()
            .status(204)
            .body(axum::body::Body::empty())
            .unwrap(),
        Err(_) => error_response("internal_error", 500),
    }
}

/// Strip sensitive fields (password_hash, totp_secret) from user for API responses
fn sanitize_user(user: users::User) -> serde_json::Value {
    serde_json::json!({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "is_admin": user.is_admin,
        "has_totp": user.totp_secret.is_some(),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    })
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_user_strips_password() {
        let user = users::User {
            id: "u1".into(),
            username: "alice".into(),
            email: "alice@test.com".into(),
            display_name: "Alice".into(),
            password_hash: "secret_hash".into(),
            totp_secret: Some(vec![1, 2, 3]),
            is_admin: true,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        };

        let sanitized = sanitize_user(user);
        assert!(sanitized.get("password_hash").is_none());
        assert!(sanitized.get("totp_secret").is_none());
        assert_eq!(sanitized["has_totp"], true);
        assert_eq!(sanitized["username"], "alice");
        assert_eq!(sanitized["is_admin"], true);
    }

    #[test]
    fn test_sanitize_user_no_totp() {
        let user = users::User {
            id: "u2".into(),
            username: "bob".into(),
            email: "bob@test.com".into(),
            display_name: "Bob".into(),
            password_hash: "h".into(),
            totp_secret: None,
            is_admin: false,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        };

        let sanitized = sanitize_user(user);
        assert_eq!(sanitized["has_totp"], false);
    }
}
