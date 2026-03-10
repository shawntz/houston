pub mod login;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(login::routes())
}
