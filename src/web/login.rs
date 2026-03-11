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
            --primary: 240 5.9% 10%;
            --primary-foreground: 0 0% 98%;
            --secondary: 240 4.8% 95.9%;
            --muted: 240 4.8% 95.9%;
            --muted-foreground: 240 3.8% 46.1%;
            --destructive: 0 84.2% 60.2%;
            --border: 240 5.9% 90%;
            --input: 240 5.9% 90%;
            --ring: 240 5.9% 10%;
            --radius: 0.625rem;
            --accent: 217 91% 60%;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        @keyframes fadeUp {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        @keyframes scaleIn {{
            from {{ opacity: 0; transform: scale(0.96); }}
            to {{ opacity: 1; transform: scale(1); }}
        }}
        @keyframes shimmer {{
            0% {{ background-position: -200% 0; }}
            100% {{ background-position: 200% 0; }}
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        @keyframes pulse-ring {{
            0% {{ transform: scale(0.95); opacity: 1; }}
            50% {{ transform: scale(1); opacity: 0.8; }}
            100% {{ transform: scale(0.95); opacity: 1; }}
        }}
        @keyframes gradient-shift {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}
        @keyframes check-draw {{
            from {{ stroke-dashoffset: 24; }}
            to {{ stroke-dashoffset: 0; }}
        }}
        @keyframes success-pop {{
            0% {{ transform: scale(0); opacity: 0; }}
            50% {{ transform: scale(1.15); }}
            100% {{ transform: scale(1); opacity: 1; }}
        }}
        @keyframes field-focus-glow {{
            0% {{ box-shadow: 0 0 0 2px hsl(var(--ring) / 0); }}
            100% {{ box-shadow: 0 0 0 2px hsl(var(--ring) / 0.15); }}
        }}
        @keyframes shake {{
            0%, 100% {{ transform: translateX(0); }}
            15%, 45%, 75% {{ transform: translateX(-6px); }}
            30%, 60%, 90% {{ transform: translateX(6px); }}
        }}
        @keyframes alert-in {{
            from {{ opacity: 0; transform: translateY(-8px) scale(0.98); }}
            to {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: hsl(var(--muted));
            color: hsl(var(--foreground));
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
            overflow: hidden;
        }}

        .scene {{
            display: flex;
            flex-direction: column;
            align-items: center;
            animation: fadeIn 0.5s ease-out;
        }}

        .brand {{
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.035em;
            color: hsl(var(--foreground));
            margin-bottom: 2rem;
            animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .brand-dot {{
            width: 8px; height: 8px;
            background: hsl(var(--accent));
            border-radius: 50%;
            animation: pulse-ring 2s ease-in-out infinite;
        }}

        .card {{
            background: hsl(var(--card));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 2.25rem;
            width: 100%;
            max-width: 400px;
            animation: scaleIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.1s both;
            position: relative;
            overflow: hidden;
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.03), 0 4px 24px -2px rgb(0 0 0 / 0.06);
        }}
        .card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, hsl(var(--accent)), hsl(260 80% 60%), hsl(var(--accent)));
            background-size: 200% 100%;
            animation: gradient-shift 3s ease infinite;
            opacity: 0.8;
        }}

        .card-title {{
            font-size: 1.375rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            text-align: center;
            margin-bottom: 0.25rem;
            animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both;
        }}
        .card-desc {{
            text-align: center;
            font-size: 0.875rem;
            color: hsl(var(--muted-foreground));
            margin-bottom: 1.75rem;
            animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.2s both;
        }}

        .alert {{
            background: hsl(var(--destructive) / 0.08);
            color: hsl(var(--destructive));
            border: 1px solid hsl(var(--destructive) / 0.15);
            padding: 0.625rem 0.875rem;
            border-radius: var(--radius);
            font-size: 0.8125rem;
            margin-bottom: 1.25rem;
            animation: alert-in 0.35s cubic-bezier(0.16, 1, 0.3, 1) both;
        }}

        .field {{
            margin-bottom: 1.125rem;
            animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) both;
        }}
        .field:nth-child(1) {{ animation-delay: 0.25s; }}
        .field:nth-child(2) {{ animation-delay: 0.3s; }}
        .field:nth-child(3) {{ animation-delay: 0.35s; }}

        .field label {{
            display: block;
            font-size: 0.8125rem;
            font-weight: 600;
            margin-bottom: 0.4rem;
            color: hsl(var(--foreground));
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        .field input {{
            width: 100%;
            padding: 0.625rem 0.875rem;
            border: 1px solid hsl(var(--input));
            border-radius: var(--radius);
            font-size: 0.9rem;
            font-family: inherit;
            background: hsl(var(--muted) / 0.35);
            color: hsl(var(--foreground));
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
        }}
        .field input:focus {{
            border-color: hsl(var(--accent));
            box-shadow: 0 0 0 3px hsl(var(--accent) / 0.12);
            background: hsl(var(--card));
        }}
        .field input::placeholder {{
            color: hsl(var(--muted-foreground) / 0.6);
        }}

        .btn {{
            width: 100%;
            padding: 0.625rem 1rem;
            font-family: inherit;
            font-size: 0.875rem;
            font-weight: 600;
            border-radius: var(--radius);
            cursor: pointer;
            border: 1px solid transparent;
            outline: none;
            position: relative;
            overflow: hidden;
            transition: transform 0.15s, box-shadow 0.15s, opacity 0.15s;
        }}
        .btn:active {{ transform: scale(0.98); }}
        .btn:focus-visible {{
            box-shadow: 0 0 0 3px hsl(var(--accent) / 0.2);
        }}

        .btn-primary {{
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
            animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.35s both;
        }}
        .btn-primary:hover {{
            box-shadow: 0 2px 8px hsl(var(--primary) / 0.25);
        }}
        .btn-primary::after {{
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, transparent, hsl(0 0% 100% / 0.08), transparent);
            background-size: 200% 100%;
            animation: shimmer 2.5s ease-in-out infinite;
            pointer-events: none;
        }}

        .btn-outline {{
            background: transparent;
            border-color: hsl(var(--border));
            color: hsl(var(--foreground));
            animation: fadeUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.45s both;
        }}
        .btn-outline:hover {{
            background: hsl(var(--secondary));
            border-color: hsl(var(--input));
        }}

        .btn-content {{ display: flex; align-items: center; justify-content: center; gap: 0.5rem; }}

        .divider {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin: 1.25rem 0;
            color: hsl(var(--muted-foreground) / 0.6);
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            animation: fadeIn 0.4s ease 0.4s both;
        }}
        .divider::before, .divider::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: hsl(var(--border));
        }}

        /* Loading overlay */
        .loading-overlay {{
            position: absolute;
            inset: 0;
            background: hsl(var(--card) / 0.92);
            backdrop-filter: blur(4px);
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.25rem;
            z-index: 10;
            animation: fadeIn 0.25s ease;
        }}
        .loading-overlay.active {{ display: flex; }}

        .spinner-container {{
            position: relative;
            width: 48px; height: 48px;
        }}
        .spinner {{
            width: 48px; height: 48px;
            border: 2.5px solid hsl(var(--border));
            border-top-color: hsl(var(--accent));
            border-radius: 50%;
            animation: spin 0.8s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite;
        }}
        .spinner-inner {{
            position: absolute;
            inset: 6px;
            border: 2px solid transparent;
            border-bottom-color: hsl(260 80% 60% / 0.5);
            border-radius: 50%;
            animation: spin 1.2s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite reverse;
        }}
        .loading-text {{
            font-size: 0.8125rem;
            font-weight: 500;
            color: hsl(var(--muted-foreground));
            animation: pulse-ring 1.5s ease-in-out infinite;
        }}

        /* Success state */
        .success-overlay {{
            position: absolute;
            inset: 0;
            background: hsl(var(--card) / 0.95);
            backdrop-filter: blur(4px);
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            z-index: 10;
        }}
        .success-overlay.active {{ display: flex; }}

        .success-check {{
            width: 56px; height: 56px;
            animation: success-pop 0.5s cubic-bezier(0.16, 1, 0.3, 1) both;
        }}
        .success-check circle {{
            fill: hsl(145 63% 42%);
        }}
        .success-check polyline {{
            stroke: white;
            stroke-width: 2.5;
            stroke-linecap: round;
            stroke-linejoin: round;
            fill: none;
            stroke-dasharray: 24;
            stroke-dashoffset: 24;
            animation: check-draw 0.4s ease 0.3s forwards;
        }}
        .success-text {{
            font-size: 0.875rem;
            font-weight: 600;
            color: hsl(var(--foreground));
            animation: fadeUp 0.4s ease 0.2s both;
        }}
        .success-subtext {{
            font-size: 0.8125rem;
            color: hsl(var(--muted-foreground));
            animation: fadeUp 0.4s ease 0.35s both;
        }}

        .card.shake {{ animation: shake 0.5s cubic-bezier(0.36, 0.07, 0.19, 0.97) both; }}

        .passkey-icon {{
            width: 16px; height: 16px;
            fill: none;
            stroke: currentColor;
            stroke-width: 2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }}

        .footer {{
            margin-top: 2rem;
            font-size: 0.75rem;
            color: hsl(var(--muted-foreground) / 0.5);
            animation: fadeIn 0.5s ease 0.6s both;
        }}
    </style>
</head>
<body>
    <div class="scene">
        <div class="brand"><span class="brand-dot"></span> houston</div>
        <div class="card" id="card">
            <div class="loading-overlay" id="loading">
                <div class="spinner-container">
                    <div class="spinner"></div>
                    <div class="spinner-inner"></div>
                </div>
                <div class="loading-text">Authenticating...</div>
            </div>
            <div class="success-overlay" id="success">
                <svg class="success-check" viewBox="0 0 56 56">
                    <circle cx="28" cy="28" r="28"/>
                    <polyline points="17 29 25 37 39 21"/>
                </svg>
                <div class="success-text">Welcome back</div>
                <div class="success-subtext">Redirecting you now...</div>
            </div>
            <h1 class="card-title">Sign In</h1>
            <p class="card-desc">Enter your credentials to continue.</p>
            {error_html}
            <form method="POST" action="/login/password" id="login-form">
                {redirect_input}
                <div class="field">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus placeholder="Enter your username" autocomplete="username">
                </div>
                <div class="field">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="Enter your password" autocomplete="current-password">
                </div>
                <button class="btn btn-primary" type="submit" id="submit-btn">
                    <span class="btn-content">Sign In</span>
                </button>
            </form>
            <div class="divider">or continue with</div>
            <button class="btn btn-outline" id="passkey-btn" onclick="startPasskeyAuth()">
                <span class="btn-content">
                    <svg class="passkey-icon" viewBox="0 0 24 24"><path d="M15 7a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z"/><path d="M11 13a4 4 0 0 0-4 4v1h8v-1a4 4 0 0 0-4-4Z"/><path d="M19 10l-1.5 1.5"/><path d="M21 8l-4 4"/></svg>
                    Passkey
                </span>
            </button>
        </div>
        <div class="footer">Secured by houston</div>
    </div>
    <script>
        const form = document.getElementById('login-form');
        const card = document.getElementById('card');
        const loading = document.getElementById('loading');
        const success = document.getElementById('success');

        // Shake card if there's an error
        if (document.querySelector('.alert')) {{
            card.classList.add('shake');
            card.addEventListener('animationend', () => card.classList.remove('shake'));
        }}

        form.addEventListener('submit', function(e) {{
            // Show loading spinner
            loading.classList.add('active');

            // Let the form submit naturally after showing the spinner.
            // The spinner provides visual feedback during the server round-trip.
            // If the server returns an error page, the loading state resets.
        }});

        async function startPasskeyAuth() {{
            // WebAuthn flow will be implemented in a later task
        }}
    </script>
</body>
</html>"#)
}
