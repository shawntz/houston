use axum::{
    extract::{Query, State},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::db::audit;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/audit-log", get(query_audit_log))
}

#[derive(Deserialize)]
struct AuditQueryParams {
    action: Option<String>,
    user_id: Option<String>,
    limit: Option<u32>,
}

async fn query_audit_log(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQueryParams>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(e) = super::users::require_admin_from_headers(&state, &headers) {
        return e;
    }

    let query = audit::AuditQuery {
        action: params.action,
        user_id: params.user_id,
        limit: params.limit,
    };

    let db = state.db.lock().unwrap();
    match audit::query_audit_log(&db, &query) {
        Ok(records) => Json(records).into_response(),
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
