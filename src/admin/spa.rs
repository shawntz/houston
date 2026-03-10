use axum::{
    extract::Path,
    response::Response,
    routing::get,
    Router,
};
use rust_embed::Embed;
use std::sync::Arc;
use crate::server::AppState;

#[derive(Embed)]
#[folder = "admin-ui/dist/"]
struct AdminAssets;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin", get(index))
        .route("/admin/{*path}", get(serve_asset))
}

async fn index() -> Response {
    serve_file("index.html")
}

async fn serve_asset(Path(path): Path<String>) -> Response {
    // Try the exact path first, then fall back to index.html for SPA routing
    if AdminAssets::get(&path).is_some() {
        serve_file(&path)
    } else {
        serve_file("index.html")
    }
}

fn serve_file(path: &str) -> Response {
    match AdminAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(200)
                .header("Content-Type", mime)
                .body(axum::body::Body::from(content.data.to_vec()))
                .unwrap()
        }
        None => Response::builder()
            .status(404)
            .body(axum::body::Body::from("Not Found"))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_assets_contain_index() {
        assert!(AdminAssets::get("index.html").is_some());
    }

    #[test]
    fn test_embedded_assets_contain_js() {
        // At least one JS file should be present
        let has_js = AdminAssets::iter().any(|f| f.ends_with(".js"));
        assert!(has_js);
    }
}
