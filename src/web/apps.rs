use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use crate::auth::session;
use crate::db::{apps, sessions, users};
use crate::middleware::auth::extract_session_token;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(app_drawer))
}

async fn app_drawer(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Manual session check — redirect to /login on failure (not 401 JSON)
    let token = match extract_session_token(&headers, &state.config.session.cookie_name) {
        Some(t) => t,
        None => return Redirect::to("/login").into_response(),
    };

    let token_hash = session::hash_token(&token);
    let db = state.db.lock().unwrap();

    let sess = match sessions::get_valid_session_by_token_hash(&db, &token_hash) {
        Ok(Some(s)) => s,
        _ => return Redirect::to("/login").into_response(),
    };

    let user = match users::get_user_by_id(&db, &sess.user_id) {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login").into_response(),
    };

    let user_apps = apps::get_apps_for_user_with_details(&db, &user.id).unwrap_or_default();

    let admin_link = if user.is_admin {
        r#"<a href="/admin" class="admin-link">Admin Dashboard</a>"#
    } else {
        ""
    };

    let cards_html = if user_apps.is_empty() {
        r#"<div class="empty-state">
            <div class="empty-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="48" height="48">
                    <rect x="3" y="3" width="7" height="7" rx="1"/>
                    <rect x="14" y="3" width="7" height="7" rx="1"/>
                    <rect x="3" y="14" width="7" height="7" rx="1"/>
                    <rect x="14" y="14" width="7" height="7" rx="1"/>
                </svg>
            </div>
            <p class="empty-title">No apps assigned</p>
            <p class="empty-desc">Ask your administrator to assign applications to your account.</p>
        </div>"#.to_string()
    } else {
        let mut html = String::from(r#"<div class="app-grid">"#);
        for app in &user_apps {
            let initial = app.name.chars().next().unwrap_or('?').to_uppercase().to_string();
            let badge_class = match app.protocol.as_str() {
                "oidc" => "badge-oidc",
                "saml" => "badge-saml",
                "bookmark" => "badge-bookmark",
                _ => "",
            };
            let badge_label = app.protocol.to_uppercase();

            if app.protocol == "bookmark" {
                let url = app.bookmark_url.as_deref().unwrap_or("#");
                html.push_str(&format!(
                    r#"<a href="{url}" target="_blank" rel="noopener noreferrer" class="app-card app-card-link">
                        <div class="app-initial">{initial}</div>
                        <div class="app-info">
                            <div class="app-name">{name}</div>
                            <span class="badge {badge_class}">{badge_label}</span>
                        </div>
                        <svg class="external-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                    </a>"#,
                    url = url, initial = initial, name = app.name, badge_class = badge_class, badge_label = badge_label
                ));
            } else {
                html.push_str(&format!(
                    r#"<div class="app-card">
                        <div class="app-initial">{initial}</div>
                        <div class="app-info">
                            <div class="app-name">{name}</div>
                            <span class="badge {badge_class}">{badge_label}</span>
                        </div>
                        <span class="sso-label">SSO</span>
                    </div>"#,
                    initial = initial, name = app.name, badge_class = badge_class, badge_label = badge_label
                ));
            }
        }
        html.push_str("</div>");
        html
    };

    let display_name = if user.display_name.is_empty() {
        &user.username
    } else {
        &user.display_name
    };

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>My Apps - Houston</title>
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

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: hsl(var(--muted));
            color: hsl(var(--foreground));
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
        }}

        .header {{
            background: hsl(var(--card));
            border-bottom: 1px solid hsl(var(--border));
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }}
        .brand {{
            font-size: 1.125rem;
            font-weight: 700;
            letter-spacing: -0.035em;
            color: hsl(var(--foreground));
            display: flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }}
        .admin-link {{
            font-size: 0.8125rem;
            font-weight: 500;
            color: hsl(var(--accent));
            text-decoration: none;
            padding: 0.375rem 0.75rem;
            border-radius: var(--radius);
            transition: background 0.15s;
        }}
        .admin-link:hover {{
            background: hsl(var(--accent) / 0.08);
        }}
        .header-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .user-info {{
            font-size: 0.875rem;
            color: hsl(var(--muted-foreground));
        }}
        .user-info strong {{
            color: hsl(var(--foreground));
            font-weight: 600;
        }}
        .btn-logout {{
            font-family: inherit;
            font-size: 0.8125rem;
            font-weight: 500;
            color: hsl(var(--muted-foreground));
            background: transparent;
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 0.375rem 0.875rem;
            cursor: pointer;
            transition: background 0.15s, color 0.15s;
        }}
        .btn-logout:hover {{
            background: hsl(var(--destructive) / 0.08);
            color: hsl(var(--destructive));
            border-color: hsl(var(--destructive) / 0.2);
        }}

        .main {{
            max-width: 960px;
            margin: 2rem auto;
            padding: 0 1.5rem;
        }}
        .page-title {{
            font-size: 1.375rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            margin-bottom: 0.25rem;
        }}
        .page-desc {{
            font-size: 0.875rem;
            color: hsl(var(--muted-foreground));
            margin-bottom: 1.5rem;
        }}

        .app-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 1rem;
        }}

        .app-card {{
            background: hsl(var(--card));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: box-shadow 0.15s, border-color 0.15s;
            text-decoration: none;
            color: inherit;
        }}
        .app-card:hover {{
            box-shadow: 0 2px 8px rgb(0 0 0 / 0.06);
            border-color: hsl(var(--input));
        }}
        .app-card-link:hover {{
            border-color: hsl(var(--accent) / 0.4);
        }}

        .app-initial {{
            width: 44px;
            height: 44px;
            border-radius: var(--radius);
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.125rem;
            font-weight: 700;
            flex-shrink: 0;
        }}
        .app-info {{
            flex: 1;
            min-width: 0;
        }}
        .app-name {{
            font-weight: 600;
            font-size: 0.9375rem;
            margin-bottom: 0.25rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .badge {{
            display: inline-block;
            padding: 0.0625rem 0.4375rem;
            font-size: 0.6875rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}
        .badge-oidc {{
            background: hsl(217 91% 60% / 0.1);
            color: hsl(217 91% 50%);
        }}
        .badge-saml {{
            background: hsl(145 63% 42% / 0.1);
            color: hsl(145 63% 35%);
        }}
        .badge-bookmark {{
            background: hsl(35 92% 50% / 0.1);
            color: hsl(35 92% 40%);
        }}

        .sso-label {{
            font-size: 0.6875rem;
            font-weight: 500;
            color: hsl(var(--muted-foreground));
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .external-icon {{
            width: 16px;
            height: 16px;
            color: hsl(var(--muted-foreground));
            flex-shrink: 0;
        }}

        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
        }}
        .empty-icon {{
            color: hsl(var(--muted-foreground) / 0.3);
            margin-bottom: 1rem;
        }}
        .empty-title {{
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }}
        .empty-desc {{
            font-size: 0.875rem;
            color: hsl(var(--muted-foreground));
        }}

        .footer {{
            text-align: center;
            padding: 2rem;
            font-size: 0.75rem;
            color: hsl(var(--muted-foreground) / 0.5);
        }}
        .footer a {{
            color: inherit;
            text-decoration: none;
        }}
        .footer a:hover {{
            color: hsl(var(--muted-foreground));
        }}
        .version {{
            margin-top: 0.25rem;
            font-size: 0.6875rem;
            opacity: 0.6;
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-left">
            <span class="brand">Houston</span>
            {admin_link}
        </div>
        <div class="header-right">
            <span class="user-info">Signed in as <strong>{display_name}</strong></span>
            <form method="POST" action="/logout" style="margin:0">
                <button type="submit" class="btn-logout">Sign Out</button>
            </form>
        </div>
    </header>
    <main class="main">
        <h1 class="page-title">My Apps</h1>
        <p class="page-desc">Applications assigned to your account.</p>
        {cards_html}
    </main>
    <footer class="footer">
        <a href="https://github.com/shawntz/houston" target="_blank">&copy; Shawn Schwartz 2026 &mdash; All Rights Reserved.</a>
        <div class="version">v{version}</div>
    </footer>
</body>
</html>"#,
        admin_link = admin_link,
        display_name = display_name,
        cards_html = cards_html,
        version = env!("CARGO_PKG_VERSION"),
    );

    Html(html).into_response()
}
