use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use std::sync::Arc;
use webauthn_rs::prelude::*;
use crate::auth::webauthn as wa;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/users/{user_id}/webauthn/register-start", post(register_start))
        .route("/api/admin/users/{user_id}/webauthn/register-finish", post(register_finish))
        .route("/login/webauthn/challenge", post(auth_challenge))
        .route("/login/webauthn/verify", post(auth_verify))
}

async fn register_start(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = crate::admin::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    let user = match crate::db::users::get_user_by_id(&db, &user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return error_response("user not found", 404),
        Err(_) => return error_response("internal_error", 500),
    };

    let existing_creds = wa::load_credentials(&db, &user_id).unwrap_or_default();
    drop(db);

    let user_unique_id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4());

    let exclude = existing_creds.iter().map(|c| c.cred_id().clone()).collect::<Vec<_>>();

    match state.webauthn.start_passkey_registration(
        user_unique_id,
        &user.username,
        &user.display_name,
        Some(exclude),
    ) {
        Ok((ccr, reg_state)) => {
            state.webauthn_state.reg_states.lock().unwrap()
                .insert(user_id.clone(), reg_state);
            Json(serde_json::to_value(&ccr).unwrap()).into_response()
        }
        Err(e) => error_response(&format!("webauthn error: {e}"), 500),
    }
}

#[derive(serde::Deserialize)]
struct RegisterFinishBody {
    credential: RegisterPublicKeyCredential,
    name: Option<String>,
}

async fn register_finish(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterFinishBody>,
) -> Response {
    if let Err(e) = crate::admin::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let reg_state = state.webauthn_state.reg_states.lock().unwrap()
        .remove(&user_id);

    let reg_state = match reg_state {
        Some(s) => s,
        None => return error_response("no pending registration", 400),
    };

    match state.webauthn.finish_passkey_registration(&body.credential, &reg_state) {
        Ok(passkey) => {
            let db = state.db.lock().unwrap();
            let name = body.name.as_deref().unwrap_or("Security Key");
            match wa::save_credential(&db, &user_id, &passkey, name) {
                Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
                Err(_) => error_response("failed to save credential", 500),
            }
        }
        Err(e) => error_response(&format!("registration failed: {e}"), 400),
    }
}

#[derive(serde::Deserialize)]
struct AuthChallengeBody {
    username: String,
}

async fn auth_challenge(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthChallengeBody>,
) -> Response {
    let db = state.db.lock().unwrap();
    let user = match crate::db::users::get_user_by_username(&db, &body.username) {
        Ok(Some(u)) => u,
        _ => return error_response("invalid_credentials", 401),
    };

    let creds = wa::load_credentials(&db, &user.id).unwrap_or_default();
    drop(db);

    if creds.is_empty() {
        return error_response("no passkeys registered", 400);
    }

    match state.webauthn.start_passkey_authentication(&creds) {
        Ok((rcr, auth_state)) => {
            state.webauthn_state.auth_states.lock().unwrap()
                .insert(user.id.clone(), auth_state);
            Json(serde_json::json!({
                "challenge": serde_json::to_value(&rcr).unwrap(),
                "user_id": user.id,
            })).into_response()
        }
        Err(e) => error_response(&format!("webauthn error: {e}"), 500),
    }
}

#[derive(serde::Deserialize)]
struct AuthVerifyBody {
    user_id: String,
    credential: PublicKeyCredential,
}

async fn auth_verify(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AuthVerifyBody>,
) -> Response {
    let auth_state = state.webauthn_state.auth_states.lock().unwrap()
        .remove(&body.user_id);

    let auth_state = match auth_state {
        Some(s) => s,
        None => return error_response("no pending authentication", 400),
    };

    let auth_result = match state.webauthn.finish_passkey_authentication(&body.credential, &auth_state) {
        Ok(r) => r,
        Err(e) => return error_response(&format!("authentication failed: {e}"), 401),
    };

    // Update credential counter
    let db = state.db.lock().unwrap();
    let mut creds = wa::load_credentials(&db, &body.user_id).unwrap_or_default();
    for cred in &mut creds {
        cred.update_credential(&auth_result);
    }
    for cred in &creds {
        let _ = wa::update_credential(&db, cred);
    }

    // Create session
    let ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let ua = headers.get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let token = crate::auth::session::generate_session_token();
    let token_hash = crate::auth::session::hash_token(&token);
    let ttl = state.config.session.ttl_seconds;

    match crate::db::sessions::create_session(&db, &body.user_id, &token_hash, &ip, &ua, ttl as i64) {
        Ok(_) => {
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                state.config.session.cookie_name, token, ttl
            );
            Response::builder()
                .status(200)
                .header("Set-Cookie", cookie)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"status":"ok"}"#))
                .unwrap()
        }
        Err(_) => error_response("session creation failed", 500),
    }
}

fn error_response(error: &str, status: u16) -> Response {
    let body = serde_json::json!({ "error": error });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}
