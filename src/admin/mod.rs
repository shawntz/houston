pub mod apps;
pub mod audit;
pub mod sessions;
pub mod users;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(users::routes())
        .merge(apps::routes())
        .merge(sessions::routes())
        .merge(audit::routes())
}
