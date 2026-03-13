pub mod apps;
pub mod audit;
pub mod sessions;
pub mod spa;
pub mod users;

use std::sync::Arc;
use axum::{Router, routing::get, response::Json};
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/version", get(get_version))
        .merge(users::routes())
        .merge(apps::routes())
        .merge(assignments::routes())
        .merge(sessions::routes())
        .merge(audit::routes())
        .merge(spa::routes())
}

async fn get_version() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}
