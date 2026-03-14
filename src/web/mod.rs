pub mod apps;
pub mod login;
pub mod webauthn;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes(_state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(apps::routes())
        .merge(login::routes())
        .merge(webauthn::routes())
}
