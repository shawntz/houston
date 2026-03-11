use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;
use crate::server::AppState;
use crate::auth::session;
use crate::db::{apps, sessions};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/saml/sso", get(sso_redirect))
}

#[derive(Deserialize)]
struct SsoQuery {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

async fn sso_redirect(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SsoQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let saml_request = match &params.saml_request {
        Some(r) => r,
        None => return Html("Missing SAMLRequest parameter".to_string()).into_response(),
    };

    // Decode SAMLRequest (base64 + deflate for HTTP-Redirect binding)
    let decoded = match base64::engine::general_purpose::STANDARD.decode(saml_request) {
        Ok(d) => d,
        Err(_) => return Html("Invalid SAMLRequest encoding".to_string()).into_response(),
    };

    // Inflate (deflated) data
    let xml_bytes = match inflate_saml_request(&decoded) {
        Some(b) => b,
        None => decoded, // might not be deflated
    };

    let xml_str = String::from_utf8_lossy(&xml_bytes);

    // Extract entity_id from AuthnRequest (simple XML parsing)
    let issuer = extract_issuer(&xml_str);
    let request_id = extract_request_id(&xml_str);

    // Look up SP by entity_id
    let db = state.db.lock().unwrap();
    let app = issuer.as_deref().and_then(|eid| {
        apps::get_app_by_entity_id(&db, eid).ok().flatten()
    });

    let app = match app {
        Some(a) => a,
        None => return Html("Unknown service provider".to_string()).into_response(),
    };

    // Check for session
    let session_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{}=", state.config.session.cookie_name)))
                .map(|c| c.splitn(2, '=').nth(1).unwrap_or("").to_string())
        });

    let valid_session = if let Some(ref token) = session_cookie {
        let token_hash = session::hash_token(token);
        sessions::get_valid_session_by_token_hash(&db, &token_hash).ok().flatten()
    } else {
        None
    };

    match valid_session {
        None => {
            // Redirect to login, preserving the full SAML query string
            let mut original_url = "/saml/sso".to_string();
            let mut query_parts = Vec::new();
            if let Some(ref req) = params.saml_request {
                query_parts.push(format!("SAMLRequest={}", urlencoding::encode(req)));
            }
            if let Some(ref rs) = params.relay_state {
                query_parts.push(format!("RelayState={}", urlencoding::encode(rs)));
            }
            if !query_parts.is_empty() {
                original_url = format!("{}?{}", original_url, query_parts.join("&"));
            }
            let redirect = format!("/login?redirect_to={}", urlencoding::encode(&original_url));
            Redirect::to(&redirect).into_response()
        }
        Some(sess) => {
            // Build SAML Response
            let user = crate::db::users::get_user_by_id(&db, &sess.user_id).ok().flatten();
            let user = match user {
                Some(u) => u,
                None => return Html("User not found".to_string()).into_response(),
            };

            let acs_url = app.acs_url.as_deref().unwrap_or("");
            let issuer_url = &state.config.server.external_url;
            let now = chrono::Utc::now();
            let not_on_or_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
            let instant = now.format("%Y-%m-%dT%H:%M:%SZ");
            let response_id = format!("_resp_{}", uuid::Uuid::new_v4());
            let assertion_id = format!("_assert_{}", uuid::Uuid::new_v4());

            let in_response_to = request_id.as_deref().unwrap_or("");

            let saml_response = format!(r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{response_id}"
  InResponseTo="{in_response_to}"
  IssueInstant="{instant}"
  Destination="{acs_url}"
  Version="2.0">
  <saml:Issuer>{issuer_url}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{assertion_id}" IssueInstant="{instant}" Version="2.0">
    <saml:Issuer>{issuer_url}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{in_response_to}"
          Recipient="{acs_url}"
          NotOnOrAfter="{not_on_or_after}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{instant}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{sp_entity_id}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{instant}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>{display_name}</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
                email = user.email,
                display_name = user.display_name,
                sp_entity_id = app.entity_id.as_deref().unwrap_or(""),
            );

            // Base64 encode for POST binding
            let encoded_response = base64::engine::general_purpose::STANDARD.encode(saml_response.as_bytes());
            let relay_state = params.relay_state.as_deref().unwrap_or("");

            // Auto-submit form (HTTP-POST binding)
            let html = format!(r#"<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form method="POST" action="{acs_url}">
  <input type="hidden" name="SAMLResponse" value="{encoded_response}"/>
  <input type="hidden" name="RelayState" value="{relay_state}"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>"#);

            Html(html).into_response()
        }
    }
}

fn inflate_saml_request(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut inflated = Vec::new();
    decoder.read_to_end(&mut inflated).ok()?;
    Some(inflated)
}

fn extract_issuer(xml: &str) -> Option<String> {
    // Simple extraction — look for <saml:Issuer> or <Issuer>
    let patterns = ["<saml:Issuer>", "<Issuer>"];
    for pattern in &patterns {
        if let Some(start) = xml.find(pattern) {
            let rest = &xml[start + pattern.len()..];
            if let Some(end) = rest.find('<') {
                return Some(rest[..end].trim().to_string());
            }
        }
    }
    None
}

fn extract_request_id(xml: &str) -> Option<String> {
    // Look for ID="..." in AuthnRequest
    if let Some(start) = xml.find("ID=\"") {
        let rest = &xml[start + 4..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}
