pub mod metadata;
pub mod sso;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(metadata::routes())
        .merge(sso::routes())
}
