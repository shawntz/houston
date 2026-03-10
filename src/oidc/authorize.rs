use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use ring::digest;
use serde::Deserialize;
use std::sync::Arc;
use crate::server::AppState;
use crate::auth::session;
use crate::db::{apps, sessions};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/oauth/authorize", get(authorize))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub fn validate_authorize_params(req: &AuthorizeRequest) -> Result<(), String> {
    if req.response_type != "code" {
        return Err("unsupported_response_type: only 'code' is supported".into());
    }
    if req.code_challenge.is_none() {
        return Err("invalid_request: code_challenge is required (PKCE)".into());
    }
    let method = req.code_challenge_method.as_deref().unwrap_or("plain");
    if method != "S256" {
        return Err("invalid_request: only S256 code_challenge_method is supported".into());
    }
    Ok(())
}

async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Validate params
    if let Err(e) = validate_authorize_params(&params) {
        return error_redirect(&params.redirect_uri, &e, params.state.as_deref());
    }

    let db = state.db.lock().unwrap();

    // Lookup app by client_id
    let app = match apps::get_app_by_client_id(&db, &params.client_id) {
        Ok(Some(app)) => app,
        _ => return error_redirect(&params.redirect_uri, "invalid_client", params.state.as_deref()),
    };

    // Validate redirect_uri
    if let Some(ref uris_json) = app.redirect_uris {
        let uris: Vec<String> = serde_json::from_str(uris_json).unwrap_or_default();
        if !uris.contains(&params.redirect_uri) {
            return error_redirect(&params.redirect_uri, "invalid_redirect_uri", params.state.as_deref());
        }
    }

    // Check for session cookie
    let session_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{}=", state.config.session.cookie_name)))
                .map(|c| c.splitn(2, '=').nth(1).unwrap_or("").to_string())
        });

    let valid_session = if let Some(ref token) = session_cookie {
        let token_hash = session::hash_token(token);
        sessions::get_valid_session_by_token_hash(&db, &token_hash)
            .ok()
            .flatten()
    } else {
        None
    };

    match valid_session {
        None => {
            // Redirect to login, preserving the authorize request
            let login_url = format!(
                "/login?redirect_to={}",
                urlencoding::encode(&format!(
                    "/oauth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
                    params.client_id,
                    urlencoding::encode(&params.redirect_uri),
                    params.response_type,
                    params.scope.as_deref().unwrap_or("openid"),
                    params.state.as_deref().unwrap_or(""),
                    params.code_challenge.as_deref().unwrap_or(""),
                    params.code_challenge_method.as_deref().unwrap_or("S256"),
                ))
            );
            Redirect::to(&login_url).into_response()
        }
        Some(sess) => {
            // Generate authorization code
            let code = session::generate_session_token(); // reuse random token gen
            let code_hash = hex::encode(digest::digest(&digest::SHA256, code.as_bytes()));

            let scopes = params.scope.as_deref().unwrap_or("openid");
            let scopes_json = serde_json::to_string(
                &scopes.split_whitespace().collect::<Vec<_>>()
            ).unwrap_or_else(|_| "[]".to_string());

            // Store authorization code
            let _ = db.execute(
                "INSERT INTO authorization_codes (code_hash, user_id, app_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+300 seconds'))",
                rusqlite::params![
                    code_hash,
                    sess.user_id,
                    app.id,
                    params.redirect_uri,
                    scopes_json,
                    params.code_challenge.as_deref().unwrap_or(""),
                    params.code_challenge_method.as_deref().unwrap_or("S256"),
                ],
            );

            // Redirect to app with code
            let mut redirect = format!("{}?code={}", params.redirect_uri, code);
            if let Some(ref state_val) = params.state {
                redirect.push_str(&format!("&state={}", state_val));
            }
            Redirect::to(&redirect).into_response()
        }
    }
}

fn error_redirect(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut url = format!("{}?error={}", redirect_uri, urlencoding::encode(error));
    if let Some(s) = state {
        url.push_str(&format!("&state={}", s));
    }
    Redirect::to(&url).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_authorize_request() {
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: Some("xyz".into()),
            code_challenge: Some("challenge123".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert!(validate_authorize_params(&req).is_ok());
    }

    #[test]
    fn test_reject_missing_code_challenge() {
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        assert!(validate_authorize_params(&req).is_err());
    }

    #[test]
    fn test_reject_non_code_response_type() {
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "token".into(),
            scope: None,
            state: None,
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert!(validate_authorize_params(&req).is_err());
    }
}
