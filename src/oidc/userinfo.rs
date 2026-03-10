use axum::{
    extract::State,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/oauth/userinfo", get(userinfo))
}

async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Extract Bearer token
    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Bearer")
                .body(axum::body::Body::from(r#"{"error":"invalid_token"}"#))
                .unwrap();
        }
    };

    // Decode the token as JWT to get the sub claim
    // (Our access tokens are opaque, but the id_token contains user info.
    //  For simplicity, we'll decode the token if it's a JWT, otherwise reject.)
    let decoding_key = jsonwebtoken::DecodingKey::from_ed_der(&state.ed25519_keypair.public_key_bytes);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;

    let claims: serde_json::Value = match jsonwebtoken::decode(&token, &decoding_key, &validation) {
        Ok(data) => data.claims,
        Err(_) => {
            // Try looking up user by access token (treat as session token)
            // For now, return error
            return Response::builder()
                .status(401)
                .header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
                .body(axum::body::Body::from(r#"{"error":"invalid_token"}"#))
                .unwrap();
        }
    };

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");

    let db = state.db.lock().unwrap();
    let user = crate::db::users::get_user_by_id(&db, sub).ok().flatten();

    match user {
        Some(u) => {
            Json(serde_json::json!({
                "sub": u.id,
                "email": u.email,
                "name": u.display_name,
                "preferred_username": u.username,
            })).into_response()
        }
        None => {
            Response::builder()
                .status(404)
                .body(axum::body::Body::from(r#"{"error":"user_not_found"}"#))
                .unwrap()
        }
    }
}
