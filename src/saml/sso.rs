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
use crate::db::{apps, assignments, sessions};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/saml/sso", get(sso_redirect))
        .route("/saml/sso/continue/{token}", get(sso_continue))
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
            // Store SAML request server-side and pass a short token through login
            let token = uuid::Uuid::new_v4().to_string();
            {
                let mut pending = state.pending_saml.lock().unwrap();
                // Clean up expired entries (older than 5 minutes)
                let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300);
                pending.retain(|_, v| v.created_at > cutoff);

                pending.insert(token.clone(), crate::server::PendingSamlRequest {
                    saml_request: params.saml_request.clone().unwrap_or_default(),
                    relay_state: params.relay_state.clone(),
                    created_at: std::time::Instant::now(),
                });
            }
            let redirect = format!(
                "/login?redirect_to={}",
                urlencoding::encode(&format!("/saml/sso/continue/{token}"))
            );
            Redirect::to(&redirect).into_response()
        }
        Some(sess) => {
            // Check user is assigned to this app
            let assigned = assignments::is_user_assigned_to_app(&db, &sess.user_id, &app.id)
                .unwrap_or(false);
            if !assigned {
                return Html(render_access_denied_page(&app.name)).into_response();
            }

            let user = crate::db::users::get_user_by_id(&db, &sess.user_id).ok().flatten();
            let user = match user {
                Some(u) => u,
                None => return Html("User not found".to_string()).into_response(),
            };

            let acs_url = app.acs_url.as_deref().unwrap_or("");
            let relay_state = params.relay_state.as_deref().unwrap_or("");

            match build_signed_saml_post_form(
                &user, &app, request_id.as_deref(),
                &state.config.server.external_url,
                &state.rsa_private_key_der, &state.x509_cert_der,
                acs_url, relay_state,
            ) {
                Ok(html) => Html(html).into_response(),
                Err(e) => Html(format!("Failed to build SAML response: {e}")).into_response(),
            }
        }
    }
}

async fn sso_continue(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Look up the pending SAML request
    let pending = {
        let mut map = state.pending_saml.lock().unwrap();
        map.remove(&token)
    };

    let pending = match pending {
        Some(p) => p,
        None => return Html("SAML request expired or invalid. Please try again.".to_string()).into_response(),
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

    let valid_session = if let Some(ref tok) = session_cookie {
        let token_hash = session::hash_token(tok);
        let db = state.db.lock().unwrap();
        sessions::get_valid_session_by_token_hash(&db, &token_hash).ok().flatten()
    } else {
        None
    };

    let sess = match valid_session {
        Some(s) => s,
        None => return Html("Not authenticated. Please sign in first.".to_string()).into_response(),
    };

    // Decode SAMLRequest
    let decoded = match base64::engine::general_purpose::STANDARD.decode(&pending.saml_request) {
        Ok(d) => d,
        Err(_) => return Html("Invalid SAMLRequest encoding".to_string()).into_response(),
    };

    let xml_bytes = match inflate_saml_request(&decoded) {
        Some(b) => b,
        None => decoded,
    };

    let xml_str = String::from_utf8_lossy(&xml_bytes);
    let issuer = extract_issuer(&xml_str);
    let request_id = extract_request_id(&xml_str);

    let db = state.db.lock().unwrap();
    let app = issuer.as_deref().and_then(|eid| {
        apps::get_app_by_entity_id(&db, eid).ok().flatten()
    });

    let app = match app {
        Some(a) => a,
        None => return Html("Unknown service provider".to_string()).into_response(),
    };

    // Check user is assigned to this app
    let assigned = assignments::is_user_assigned_to_app(&db, &sess.user_id, &app.id)
        .unwrap_or(false);
    if !assigned {
        return Html(render_access_denied_page(&app.name)).into_response();
    }

    let user = crate::db::users::get_user_by_id(&db, &sess.user_id).ok().flatten();
    let user = match user {
        Some(u) => u,
        None => return Html("User not found".to_string()).into_response(),
    };

    let acs_url = app.acs_url.as_deref().unwrap_or("");
    let relay_state = pending.relay_state.as_deref().unwrap_or("");

    match build_signed_saml_post_form(
        &user, &app, request_id.as_deref(),
        &state.config.server.external_url,
        &state.rsa_private_key_der, &state.x509_cert_der,
        acs_url, relay_state,
    ) {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Failed to build SAML response: {e}")).into_response(),
    }
}

fn build_signed_saml_post_form(
    user: &crate::db::users::User,
    app: &crate::db::apps::App,
    request_id: Option<&str>,
    issuer_url: &str,
    rsa_private_key_der: &[u8],
    x509_cert_der: &[u8],
    acs_url: &str,
    relay_state: &str,
) -> Result<String, String> {
    let now = chrono::Utc::now();
    let not_on_or_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
    let instant = now.format("%Y-%m-%dT%H:%M:%SZ");
    let response_id = format!("_resp_{}", uuid::Uuid::new_v4());
    let assertion_id = format!("_assert_{}", uuid::Uuid::new_v4());
    let in_response_to = request_id.unwrap_or("");
    let sp_entity_id = app.entity_id.as_deref().unwrap_or("");

    let base64_cert = base64::engine::general_purpose::STANDARD.encode(x509_cert_der);

    // Build SAML Response XML with embedded ds:Signature template
    let sig_ref_uri = format!("#{response_id}");
    let saml_response_xml = format!(
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{response_id}"
  InResponseTo="{in_response_to}"
  IssueInstant="{instant}"
  Destination="{acs_url}"
  Version="2.0">
  <saml:Issuer>{issuer_url}</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="{sig_ref_uri}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{base64_cert}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
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
</samlp:Response>"##,
        email = user.email,
        display_name = user.display_name,
    );

    // Sign the XML using xmlsec (fills in DigestValue and SignatureValue)
    let signed_xml = samael::crypto::sign_xml(saml_response_xml, rsa_private_key_der)
        .map_err(|e| format!("XML signing failed: {e}"))?;

    // Base64 encode for POST binding
    let encoded_response = base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes());

    // Auto-submit form (HTTP-POST binding)
    Ok(format!(r#"<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form method="POST" action="{acs_url}">
  <input type="hidden" name="SAMLResponse" value="{encoded_response}"/>
  <input type="hidden" name="RelayState" value="{relay_state}"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>"#))
}

fn render_access_denied_page(app_name: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head><title>Access Denied</title>
<style>
  body {{ font-family: system-ui, sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }}
  .card {{ background: white; border-radius: 12px; padding: 2rem; max-width: 420px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  h1 {{ color: #d32f2f; font-size: 1.5rem; }}
  p {{ color: #555; line-height: 1.6; }}
  .version {{ margin-top: 1.5rem; font-size: 0.6875rem; color: #999; }}
</style>
</head>
<body>
<div class="card">
  <h1>Access Denied</h1>
  <p>You are not assigned to <strong>{app_name}</strong>. Please contact your administrator to request access.</p>
</div>
<div class="version">houston v{version}</div>
</body>
</html>"#, app_name = app_name, version = env!("CARGO_PKG_VERSION"))
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
    let needle = r#"ID=""#;
    if let Some(start) = xml.find(needle) {
        let rest = &xml[start + needle.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}
