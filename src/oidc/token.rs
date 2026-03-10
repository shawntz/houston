use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    routing::post,
    Form, Router,
};
use ring::digest;
use serde::Deserialize;
use std::sync::Arc;
use crate::server::AppState;
use crate::crypto::keys;
use crate::db::users;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/oauth/token", post(token_exchange))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

async fn token_exchange(
    State(state): State<Arc<AppState>>,
    Form(form): Form<TokenRequest>,
) -> Response {
    if form.grant_type != "authorization_code" {
        return error_response("unsupported_grant_type", 400);
    }

    let db = state.db.lock().unwrap();

    // Hash the presented code
    let code_hash = hex::encode(digest::digest(&digest::SHA256, form.code.as_bytes()));

    // Look up the authorization code
    let mut stmt = db.prepare(
        "SELECT code_hash, user_id, app_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at
         FROM authorization_codes WHERE code_hash = ?1"
    ).unwrap();

    let auth_code = stmt.query_row(rusqlite::params![code_hash], |row| {
        Ok(AuthCode {
            code_hash: row.get(0)?,
            user_id: row.get(1)?,
            app_id: row.get(2)?,
            redirect_uri: row.get(3)?,
            scopes: row.get(4)?,
            code_challenge: row.get(5)?,
            _code_challenge_method: row.get(6)?,
            expires_at: row.get(7)?,
        })
    });

    let auth_code = match auth_code {
        Ok(c) => c,
        Err(_) => return error_response("invalid_grant", 400),
    };

    // Delete the code immediately (one-time use)
    let _ = db.execute("DELETE FROM authorization_codes WHERE code_hash = ?1", rusqlite::params![code_hash]);

    // Check expiry
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    if auth_code.expires_at < now {
        return error_response("invalid_grant: code expired", 400);
    }

    // Verify redirect_uri matches
    if auth_code.redirect_uri != form.redirect_uri {
        return error_response("invalid_grant: redirect_uri mismatch", 400);
    }

    // Verify client_id matches
    let app = match crate::db::apps::get_app_by_id(&db, &auth_code.app_id) {
        Ok(Some(app)) if app.client_id.as_deref() == Some(&form.client_id) => app,
        _ => return error_response("invalid_client", 401),
    };

    // Verify PKCE code_verifier
    if !verify_pkce(&form.code_verifier, &auth_code.code_challenge) {
        return error_response("invalid_grant: PKCE verification failed", 400);
    }

    // Fetch user
    let user = match users::get_user_by_id(&db, &auth_code.user_id) {
        Ok(Some(u)) => u,
        _ => return error_response("invalid_grant: user not found", 400),
    };

    // Mint ID token (JWT)
    let now_ts = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": state.config.server.external_url,
        "sub": user.id,
        "aud": app.client_id,
        "exp": now_ts + 3600,
        "iat": now_ts,
        "email": user.email,
        "name": user.display_name,
    });

    let id_token = match keys::sign_jwt_ed25519(&state.ed25519_keypair, &claims) {
        Ok(t) => t,
        Err(_) => return error_response("server_error", 500),
    };

    // Generate access token (opaque for simplicity)
    let access_token = crate::auth::session::generate_session_token();

    Json(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": auth_code.scopes,
    })).into_response()
}

struct AuthCode {
    code_hash: String,
    user_id: String,
    app_id: String,
    redirect_uri: String,
    scopes: String,
    code_challenge: String,
    _code_challenge_method: String,
    expires_at: String,
}

/// Verify PKCE: SHA256(code_verifier) == code_challenge
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    use base64::Engine;
    let hash = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref());
    computed == code_challenge
}

fn error_response(error: &str, status: u16) -> Response {
    let body = serde_json::json!({ "error": error });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ring::digest;

    #[test]
    fn test_pkce_verification() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = digest::digest(&digest::SHA256, verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref());
        assert!(verify_pkce(verifier, &challenge));
    }

    #[test]
    fn test_pkce_wrong_verifier_fails() {
        let verifier = "correct-verifier";
        let hash = digest::digest(&digest::SHA256, verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref());
        assert!(!verify_pkce("wrong-verifier", &challenge));
    }
}
