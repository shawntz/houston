use axum::{
    extract::{Path, State},
    response::{Json, Response},
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use crate::db::{assignments, apps, users};
use crate::server::AppState;
use super::users::{require_admin_from_headers, error_response};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/apps/{app_id}/users", get(get_app_users))
        .route("/api/admin/apps/{app_id}/users/{user_id}", post(assign_user))
        .route("/api/admin/apps/{app_id}/users/{user_id}", delete(unassign_user))
}

async fn get_app_users(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, Response> {
    require_admin_from_headers(&state, &headers)?;

    let db = state.db.lock().unwrap();

    let app = apps::get_app_by_id(&db, &app_id)
        .ok().flatten()
        .ok_or_else(|| error_response("app not found", 404))?;

    let user_ids = assignments::get_users_for_app(&db, &app.id)
        .map_err(|_| error_response("internal error", 500))?;

    let mut result = Vec::new();
    for uid in &user_ids {
        if let Some(user) = users::get_user_by_id(&db, uid).ok().flatten() {
            result.push(serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
            }));
        }
    }

    Ok(Json(result))
}

async fn assign_user(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((app_id, user_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    require_admin_from_headers(&state, &headers)?;

    let db = state.db.lock().unwrap();

    apps::get_app_by_id(&db, &app_id)
        .ok().flatten()
        .ok_or_else(|| error_response("app not found", 404))?;

    users::get_user_by_id(&db, &user_id)
        .ok().flatten()
        .ok_or_else(|| error_response("user not found", 404))?;

    assignments::assign_user_to_app(&db, &user_id, &app_id)
        .map_err(|_| error_response("internal error", 500))?;

    Ok(Response::builder().status(204).body(axum::body::Body::empty()).unwrap())
}

async fn unassign_user(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((app_id, user_id)): Path<(String, String)>,
) -> Result<Response, Response> {
    require_admin_from_headers(&state, &headers)?;

    let db = state.db.lock().unwrap();

    assignments::unassign_user_from_app(&db, &user_id, &app_id)
        .map_err(|_| error_response("internal error", 500))?;

    Ok(Response::builder().status(204).body(axum::body::Body::empty()).unwrap())
}
