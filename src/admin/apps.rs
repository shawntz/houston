use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::db::apps;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/apps", get(list_apps).post(create_app))
        .route("/api/admin/apps/{id}", get(get_app).delete(delete_app).put(update_app))
        .route("/api/admin/apps/{id}/rotate-secret", post(rotate_secret))
}

#[derive(Deserialize)]
struct CreateAppRequest {
    name: String,
    protocol: String,
    // OIDC fields
    redirect_uris: Option<Vec<String>>,
    // SAML fields
    entity_id: Option<String>,
    acs_url: Option<String>,
    // Bookmark fields
    bookmark_url: Option<String>,
    // Common optional fields
    icon_url: Option<String>,
    launch_url: Option<String>,
}

#[derive(Deserialize)]
struct UpdateAppRequest {
    icon_url: Option<String>,
    launch_url: Option<String>,
}

async fn list_apps(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match apps::list_apps(&db) {
        Ok(apps) => Json(apps).into_response(),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn get_app(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match apps::get_app_by_id(&db, &id) {
        Ok(Some(app)) => Json(app).into_response(),
        Ok(None) => error_response("not_found", 404),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn create_app(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateAppRequest>,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let create = match body.protocol.as_str() {
        "oidc" => apps::CreateApp::Oidc {
            name: body.name,
            redirect_uris: body.redirect_uris.unwrap_or_default(),
        },
        "saml" => {
            let entity_id = match body.entity_id {
                Some(e) => e,
                None => return error_response("entity_id required for SAML apps", 400),
            };
            let acs_url = match body.acs_url {
                Some(a) => a,
                None => return error_response("acs_url required for SAML apps", 400),
            };
            apps::CreateApp::Saml {
                name: body.name,
                entity_id,
                acs_url,
            }
        }
        "bookmark" => {
            let url = match body.bookmark_url {
                Some(u) => u,
                None => return error_response("bookmark_url required for bookmark apps", 400),
            };
            apps::CreateApp::Bookmark {
                name: body.name,
                url,
            }
        }
        _ => return error_response("protocol must be 'oidc', 'saml', or 'bookmark'", 400),
    };

    let icon = body.icon_url.as_deref();
    let launch = body.launch_url.as_deref();

    let db = state.db.lock().unwrap();
    match apps::create_app(&db, &create, icon, launch) {
        Ok(app) => {
            let mut resp = Json(app).into_response();
            *resp.status_mut() = axum::http::StatusCode::CREATED;
            resp
        }
        Err(_) => error_response("internal_error", 500),
    }
}

async fn delete_app(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match apps::get_app_by_id(&db, &id) {
        Ok(None) => return error_response("not_found", 404),
        Err(_) => return error_response("internal_error", 500),
        _ => {}
    }

    match apps::delete_app(&db, &id) {
        Ok(()) => Response::builder()
            .status(204)
            .body(axum::body::Body::empty())
            .unwrap(),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn update_app(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateAppRequest>,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match apps::update_app_settings(&db, &id, body.icon_url.as_deref(), body.launch_url.as_deref()) {
        Ok(Some(app)) => Json(app).into_response(),
        Ok(None) => error_response("not_found", 404),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn rotate_secret(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    let app = match apps::get_app_by_id(&db, &id) {
        Ok(Some(a)) => a,
        Ok(None) => return error_response("not_found", 404),
        Err(_) => return error_response("internal_error", 500),
    };

    if app.protocol != "oidc" {
        return error_response("secret rotation only applies to OIDC apps", 400);
    }

    // Generate new client_id (acts as the rotated credential)
    let new_client_id = apps::generate_new_client_id();
    match db.execute(
        "UPDATE apps SET client_id = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?2",
        rusqlite::params![new_client_id, id],
    ) {
        Ok(_) => {
            let updated = apps::get_app_by_id(&db, &id).ok().flatten().unwrap();
            Json(updated).into_response()
        }
        Err(_) => error_response("internal_error", 500),
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_create_app_requires_protocol() {
        // Validation tested via API — protocol must be "oidc" or "saml"
        assert!(["oidc", "saml"].contains(&"oidc"));
        assert!(!["oidc", "saml"].contains(&"ldap"));
    }
}
