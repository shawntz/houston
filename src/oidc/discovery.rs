use axum::{extract::State, response::Json, routing::get, Router};
use base64::Engine;
use std::sync::Arc;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
}

pub fn build_discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "email", "name", "iss", "aud", "exp", "iat"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    })
}

async fn discovery(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(build_discovery_document(&state.config.server.external_url))
}

async fn jwks(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&state.ed25519_keypair.public_key_bytes);

    Json(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": state.ed25519_keypair.kid,
            "x": pub_key_b64,
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document() {
        let doc = build_discovery_document("https://id.example.com");
        assert_eq!(doc["issuer"], "https://id.example.com");
        assert_eq!(doc["authorization_endpoint"], "https://id.example.com/oauth/authorize");
        assert_eq!(doc["token_endpoint"], "https://id.example.com/oauth/token");
        assert_eq!(doc["jwks_uri"], "https://id.example.com/.well-known/jwks.json");
    }
}
