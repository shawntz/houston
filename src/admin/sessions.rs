use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Response},
    routing::{delete, get},
    Router,
};
use std::sync::Arc;
use crate::db::sessions;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/sessions", get(list_sessions))
        .route("/api/admin/sessions/{id}", delete(revoke_session))
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match sessions::list_sessions(&db) {
        Ok(sessions) => Json(sessions).into_response(),
        Err(_) => error_response("internal_error", 500),
    }
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let db = state.db.lock().unwrap();
    match sessions::get_session_by_id(&db, &id) {
        Ok(None) => return error_response("not_found", 404),
        Err(_) => return error_response("internal_error", 500),
        _ => {}
    }

    match sessions::delete_session(&db, &id) {
        Ok(()) => Response::builder()
            .status(204)
            .body(axum::body::Body::empty())
            .unwrap(),
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
