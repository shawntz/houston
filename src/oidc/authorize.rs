use axum::Router;
use std::sync::Arc;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
}
