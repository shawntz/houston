use axum::{
    extract::State,
    response::Response,
    routing::get,
    Router,
};
use std::sync::Arc;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/saml/metadata", get(metadata))
}

pub fn build_metadata_xml(entity_id: &str, sso_url: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                    WantAuthnRequestsSigned="false">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="{sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="{sso_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#)
}

async fn metadata(State(state): State<Arc<AppState>>) -> Response {
    let entity_id = &state.config.server.external_url;
    let sso_url = format!("{}/saml/sso", entity_id);
    let xml = build_metadata_xml(entity_id, &sso_url);

    Response::builder()
        .status(200)
        .header("Content-Type", "application/xml")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_xml() {
        let xml = build_metadata_xml("https://id.example.com", "https://id.example.com/saml/sso");
        assert!(xml.contains("entityID=\"https://id.example.com\""));
        assert!(xml.contains("SingleSignOnService"));
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"));
    }
}
