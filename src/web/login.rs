use axum::{
    extract::{Query, State},
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

#[derive(Deserialize, Default)]
struct LoginQuery {
    redirect_to: Option<String>,
}

async fn login_page(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> Html<String> {
    let html = render_login_page(None, query.redirect_to.as_deref());
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
    let error_html = error.map(|e| format!(r#"<div class="alert">{e}</div>"#)).unwrap_or_default();
    let redirect_input = redirect_to
        .map(|r| format!(r#"<input type="hidden" name="redirect_to" value="{r}">"#))
        .unwrap_or_default();

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign In - houston</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --background: 0 0% 100%;
            --foreground: 240 10% 3.9%;
            --card: 0 0% 100%;
            --card-foreground: 240 10% 3.9%;
            --primary: 240 5.9% 10%;
            --primary-foreground: 0 0% 98%;
            --secondary: 240 4.8% 95.9%;
            --muted: 240 4.8% 95.9%;
            --muted-foreground: 240 3.8% 46.1%;
            --destructive: 0 84.2% 60.2%;
            --border: 240 5.9% 90%;
            --input: 240 5.9% 90%;
            --ring: 240 5.9% 10%;
            --radius: 0.5rem;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: hsl(var(--muted));
            color: hsl(var(--foreground));
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }}
        .brand {{
            font-size: 1.125rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            color: hsl(var(--foreground));
            margin-bottom: 2rem;
        }}
        .card {{
            background: hsl(var(--card));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 2rem;
            width: 100%;
            max-width: 380px;
        }}
        .card-title {{
            font-size: 1.25rem;
            font-weight: 600;
            letter-spacing: -0.025em;
            text-align: center;
            margin-bottom: 0.25rem;
        }}
        .card-desc {{
            text-align: center;
            font-size: 0.875rem;
            color: hsl(var(--muted-foreground));
            margin-bottom: 1.5rem;
        }}
        .alert {{
            background: hsl(var(--destructive) / 0.1);
            color: hsl(var(--destructive));
            border: 1px solid hsl(var(--destructive) / 0.2);
            padding: 0.625rem 0.875rem;
            border-radius: var(--radius);
            font-size: 0.8125rem;
            margin-bottom: 1rem;
        }}
        .field {{
            margin-bottom: 1rem;
        }}
        .field label {{
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.375rem;
            color: hsl(var(--foreground));
        }}
        .field input {{
            width: 100%;
            padding: 0.5rem 0.75rem;
            border: 1px solid hsl(var(--input));
            border-radius: var(--radius);
            font-size: 0.875rem;
            font-family: inherit;
            background: transparent;
            color: hsl(var(--foreground));
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }}
        .field input:focus {{
            border-color: hsl(var(--ring));
            box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2);
        }}
        .field input::placeholder {{
            color: hsl(var(--muted-foreground));
        }}
        .btn {{
            width: 100%;
            padding: 0.5rem 1rem;
            font-family: inherit;
            font-size: 0.875rem;
            font-weight: 500;
            border-radius: var(--radius);
            cursor: pointer;
            border: 1px solid transparent;
            transition: opacity 0.15s;
            outline: none;
        }}
        .btn:focus-visible {{
            box-shadow: 0 0 0 2px hsl(var(--ring) / 0.2);
        }}
        .btn-primary {{
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
        }}
        .btn-primary:hover {{ opacity: 0.9; }}
        .btn-outline {{
            background: transparent;
            border-color: hsl(var(--input));
            color: hsl(var(--foreground));
        }}
        .btn-outline:hover {{
            background: hsl(var(--secondary));
        }}
        .divider {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin: 1.25rem 0;
            color: hsl(var(--muted-foreground));
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .divider::before, .divider::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: hsl(var(--border));
        }}
    </style>
</head>
<body>
    <div class="brand">houston</div>
    <div class="card">
        <h1 class="card-title">Sign In</h1>
        <p class="card-desc">Enter your credentials to continue.</p>
        {error_html}
        <form method="POST" action="/login/password">
            {redirect_input}
            <div class="field">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus placeholder="Enter your username">
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter your password">
            </div>
            <button class="btn btn-primary" type="submit">Sign In</button>
        </form>
        <div class="divider">or</div>
        <button class="btn btn-outline" id="passkey-btn" onclick="startPasskeyAuth()">
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
