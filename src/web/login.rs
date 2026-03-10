use axum::{
    extract::State,
    response::{Html, Redirect, IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::server::AppState;
use crate::auth::{password, session};
use crate::db::{users, sessions};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login/password", post(login_password))
        .route("/logout", post(logout))
}

async fn login_page(State(_state): State<Arc<AppState>>) -> Html<String> {
    let html = render_login_page(None, None);
    Html(html)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[allow(dead_code)]
    csrf_token: Option<String>,
    redirect_to: Option<String>,
}

async fn login_password(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    // Rate limiting
    if !state.login_rate_limiter.check(&form.username) {
        return Html(render_login_page(
            Some("Too many login attempts. Please try again later."),
            form.redirect_to.as_deref(),
        )).into_response();
    }

    let db = state.db.lock().unwrap();

    // Lookup user and verify password (timing-safe)
    let user = users::get_user_by_username(&db, &form.username).unwrap_or(None);
    let hash = user.as_ref().map(|u| u.password_hash.as_str());

    let valid = password::verify_password_or_dummy(&form.password, hash)
        .unwrap_or(false);

    if !valid {
        let _ = crate::db::audit::append_audit(&db, &crate::db::audit::AuditEntry {
            user_id: user.as_ref().map(|u| u.id.clone()),
            action: "login_failed".into(),
            ip_address: String::new(),
            detail: serde_json::json!({"username": form.username}),
            app_id: None,
        });

        return Html(render_login_page(
            Some("Invalid credentials."),
            form.redirect_to.as_deref(),
        )).into_response();
    }

    let user = user.unwrap();

    // Check if TOTP is enrolled
    if user.totp_secret.is_some() {
        // TODO: store pending auth state and redirect to /login/totp
        return Html(render_login_page(
            Some("TOTP not yet implemented."),
            form.redirect_to.as_deref(),
        )).into_response();
    }

    // Create session
    let token = session::generate_session_token();
    let token_hash = session::hash_token(&token);
    let _ = sessions::create_session(
        &db, &user.id, &token_hash, "", "",
        state.config.session.ttl_seconds as i64,
    );

    let _ = crate::db::audit::append_audit(&db, &crate::db::audit::AuditEntry {
        user_id: Some(user.id.clone()),
        action: "login_success".into(),
        ip_address: String::new(),
        detail: serde_json::json!({"method": "password"}),
        app_id: None,
    });

    // Set session cookie and redirect
    let cookie = format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        state.config.session.cookie_name, token, state.config.session.ttl_seconds
    );

    let redirect_to = form.redirect_to.as_deref().unwrap_or("/admin");

    Response::builder()
        .status(303)
        .header("Set-Cookie", cookie)
        .header("Location", redirect_to)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn logout(State(_state): State<Arc<AppState>>) -> Redirect {
    // TODO: extract session cookie, delete session from DB
    Redirect::to("/login")
}

fn render_login_page(error: Option<&str>, redirect_to: Option<&str>) -> String {
    let error_html = error.map(|e| format!(r#"<div class="error">{e}</div>"#)).unwrap_or_default();
    let redirect_input = redirect_to
        .map(|r| format!(r#"<input type="hidden" name="redirect_to" value="{r}">"#))
        .unwrap_or_default();

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign In - minikta</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; display: flex; justify-content: center; align-items: center;
               min-height: 100vh; }}
        .card {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                 width: 100%; max-width: 400px; }}
        h1 {{ font-size: 1.5rem; margin-bottom: 1.5rem; text-align: center; }}
        .error {{ background: #fee; color: #c33; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;
                  font-size: 0.9rem; }}
        label {{ display: block; margin-bottom: 0.25rem; font-size: 0.9rem; font-weight: 500; }}
        input[type="text"], input[type="password"] {{
            width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 4px;
            font-size: 1rem; margin-bottom: 1rem; }}
        button {{ width: 100%; padding: 0.75rem; background: #2563eb; color: white; border: none;
                  border-radius: 4px; font-size: 1rem; cursor: pointer; }}
        button:hover {{ background: #1d4ed8; }}
        .passkey-divider {{ text-align: center; margin: 1rem 0; color: #999; font-size: 0.9rem; }}
        .passkey-btn {{ background: #059669; }}
        .passkey-btn:hover {{ background: #047857; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Sign In</h1>
        {error_html}
        <form method="POST" action="/login/password">
            {redirect_input}
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required autofocus>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="passkey-divider">or</div>
        <button class="passkey-btn" id="passkey-btn" onclick="startPasskeyAuth()">
            Sign in with Passkey
        </button>
    </div>
    <script>
        async function startPasskeyAuth() {{
            // WebAuthn flow will be implemented in a later task
        }}
    </script>
</body>
</html>"#)
}
