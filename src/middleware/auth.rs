use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::Response,
};
use std::sync::Arc;
use crate::auth::session;
use crate::db::{sessions, users};
use crate::server::AppState;

/// Extractor that validates the session cookie and provides the current user.
/// Rejects with 401 if no valid session exists.
pub struct AuthUser(pub users::User);

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_session_token(&parts.headers, &state.config.session.cookie_name)
            .ok_or_else(|| unauthorized())?;

        let token_hash = session::hash_token(&token);
        let db = state.db.lock().unwrap();
        let sess = sessions::get_valid_session_by_token_hash(&db, &token_hash)
            .ok()
            .flatten()
            .ok_or_else(|| unauthorized())?;

        let user = users::get_user_by_id(&db, &sess.user_id)
            .ok()
            .flatten()
            .ok_or_else(|| unauthorized())?;

        Ok(AuthUser(user))
    }
}

/// Extractor that validates the session cookie AND checks is_admin.
/// Rejects with 401 if no session, 403 if not admin.
pub struct RequireAdmin(pub users::User);

impl FromRequestParts<Arc<AppState>> for RequireAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;

        if !user.is_admin {
            return Err(forbidden());
        }

        Ok(RequireAdmin(user))
    }
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

fn unauthorized() -> Response {
    Response::builder()
        .status(401)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"error":"unauthorized"}"#))
        .unwrap()
}

fn forbidden() -> Response {
    Response::builder()
        .status(403)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"error":"forbidden"}"#))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_session_token() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("minikta_session=abc123; other=xyz"));
        let token = extract_session_token(&headers, "minikta_session");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_session_token_missing() {
        let headers = axum::http::HeaderMap::new();
        let token = extract_session_token(&headers, "minikta_session");
        assert!(token.is_none());
    }

    #[test]
    fn test_extract_session_token_wrong_name() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("other_cookie=abc123"));
        let token = extract_session_token(&headers, "minikta_session");
        assert!(token.is_none());
    }
}
