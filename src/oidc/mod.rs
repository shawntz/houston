pub mod discovery;
pub mod authorize;
pub mod token;
pub mod userinfo;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(discovery::routes())
        .merge(authorize::routes())
        .merge(token::routes())
        .merge(userinfo::routes())
}
