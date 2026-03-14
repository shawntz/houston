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
        r#"<a href="/admin" class="nav-cmd"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/><path d="M14 9h7"/><path d="M14 15h7"/></svg>Admin Dashboard</a>"#
    } else {
        ""
    };

    let greeting_name = if user.display_name.is_empty() {
        user.username.clone()
    } else {
        user.display_name.split_whitespace().next().unwrap_or(&user.display_name).to_string()
    };

    let app_count_text = match user_apps.len() {
        0 => String::new(),
        1 => "1 application ready for launch".to_string(),
        n => format!("{n} applications ready for launch"),
    };

    let cards_html = if user_apps.is_empty() {
        r#"<div class="empty-state">
            <div class="empty-rings">
                <div class="ring ring-1"></div>
                <div class="ring ring-2"></div>
                <div class="ring ring-3"></div>
                <div class="ring-dot"></div>
            </div>
            <p class="empty-title">No transmissions detected</p>
            <p class="empty-desc">Ask your administrator to assign applications to your account.</p>
        </div>"#.to_string()
    } else {
        let mut html = String::from(r#"<div class="app-grid">"#);
        for (i, app) in user_apps.iter().enumerate() {
            let initial = app.name.chars().next().unwrap_or('?').to_uppercase().to_string();
            let (badge_class, orb_class) = match app.protocol.as_str() {
                "oidc" => ("badge-oidc", "orb-oidc"),
                "saml" => ("badge-saml", "orb-saml"),
                "bookmark" => ("badge-bookmark", "orb-bookmark"),
                _ => ("", ""),
            };
            let badge_label = app.protocol.to_uppercase();

            if app.protocol == "bookmark" {
                let url = app.bookmark_url.as_deref().unwrap_or("#");
                html.push_str(&format!(
                    r#"<a href="{url}" target="_blank" rel="noopener noreferrer" class="app-card app-card-link" style="--i:{i}">
                        <div class="app-orb {orb_class}"><span>{initial}</span></div>
                        <div class="app-info">
                            <div class="app-name">{name}</div>
                            <span class="badge {badge_class}">{badge_label}</span>
                        </div>
                        <svg class="launch-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7"/><path d="M7 7h10v10"/></svg>
                    </a>"#,
                    url = url, initial = initial, name = app.name,
                    orb_class = orb_class, badge_class = badge_class, badge_label = badge_label,
                    i = i,
                ));
            } else {
                html.push_str(&format!(
                    r#"<div class="app-card" style="--i:{i}">
                        <div class="app-orb {orb_class}"><span>{initial}</span></div>
                        <div class="app-info">
                            <div class="app-name">{name}</div>
                            <span class="badge {badge_class}">{badge_label}</span>
                        </div>
                        <span class="sso-tag"><span class="sso-dot"></span>SSO</span>
                    </div>"#,
                    initial = initial, name = app.name,
                    orb_class = orb_class, badge_class = badge_class, badge_label = badge_label,
                    i = i,
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
    <title>Houston - Launch Pad</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --space-deep: 228 25% 5%;
            --space-surface: 225 20% 10%;
            --space-elevated: 225 18% 14%;
            --space-border: 225 15% 20%;
            --space-text: 210 40% 96.5%;
            --space-text-muted: 215 20% 55%;
            --space-text-dim: 215 15% 35%;
            --glow-cyan: 199 89% 48%;
            --glow-blue: 217 91% 60%;
            --glow-purple: 263 70% 71%;
            --glow-green: 152 69% 46%;
            --glow-amber: 38 92% 50%;
            --radius: 0.75rem;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: hsl(var(--space-deep));
            color: hsl(var(--space-text));
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
            overflow-x: hidden;
        }}

        /* ── Animations ─────────────────────────── */
        @keyframes fadeUp {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes cardIn {{
            from {{ opacity: 0; transform: translateY(24px) scale(0.97); }}
            to {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.35; }}
        }}
        @keyframes float {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-6px); }}
        }}
        @keyframes shoot {{
            0% {{ transform: translateX(0) rotate(-30deg); opacity: 0; }}
            2% {{ opacity: 0.7; }}
            8% {{ transform: translateX(calc(100vw + 200px)) rotate(-30deg); opacity: 0; }}
            100% {{ opacity: 0; }}
        }}
        @keyframes hudIn {{
            from {{ opacity: 0; transform: translateY(-10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes scanline {{
            0% {{ background-position: 200% 0; }}
            100% {{ background-position: -200% 0; }}
        }}
        @keyframes ringPulse {{
            0%, 100% {{ opacity: 0.15; transform: translate(-50%, -50%) scale(1); }}
            50% {{ opacity: 0.05; transform: translate(-50%, -50%) scale(1.05); }}
        }}

        /* ── Background Layers ──────────────────── */
        #stars {{
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }}
        .bg-nebula {{
            position: fixed;
            inset: 0;
            z-index: 1;
            pointer-events: none;
            background:
                radial-gradient(ellipse 800px 600px at 15% 25%, hsl(260 50% 15% / 0.3) 0%, transparent 70%),
                radial-gradient(ellipse 600px 900px at 80% 60%, hsl(200 50% 10% / 0.2) 0%, transparent 70%),
                radial-gradient(ellipse 1000px 400px at 50% 95%, hsl(280 40% 10% / 0.15) 0%, transparent 70%);
        }}
        .bg-grid {{
            position: fixed;
            inset: 0;
            z-index: 2;
            pointer-events: none;
            background-image:
                linear-gradient(hsl(215 20% 40% / 0.025) 1px, transparent 1px),
                linear-gradient(90deg, hsl(215 20% 40% / 0.025) 1px, transparent 1px);
            background-size: 64px 64px;
        }}
        .shooting-star {{
            position: fixed;
            height: 1px;
            z-index: 3;
            pointer-events: none;
            opacity: 0;
            background: linear-gradient(90deg, hsl(var(--space-text) / 0.6), transparent);
        }}
        .ss-1 {{ width: 80px; top: 12%; left: -80px; animation: shoot 18s ease-in 3s infinite; }}
        .ss-2 {{ width: 120px; top: 38%; left: -120px; animation: shoot 24s ease-in 10s infinite; }}
        .ss-3 {{ width: 60px; top: 62%; left: -60px; animation: shoot 30s ease-in 18s infinite; }}

        /* ── HUD Header ─────────────────────────── */
        .hud {{
            position: sticky;
            top: 0;
            z-index: 20;
            background: hsl(var(--space-deep) / 0.75);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border-bottom: 1px solid hsl(var(--space-border) / 0.5);
            padding: 0.75rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            animation: hudIn 0.5s ease both;
        }}
        .hud::after {{
            content: '';
            position: absolute;
            left: 0; right: 0; bottom: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, hsl(var(--glow-cyan) / 0.25), transparent);
            background-size: 200% 100%;
            animation: scanline 4s ease-in-out infinite;
        }}
        .hud-left {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .brand {{
            font-size: 0.9375rem;
            font-weight: 800;
            letter-spacing: 0.12em;
            color: hsl(var(--space-text));
            text-transform: uppercase;
        }}
        .status {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.6875rem;
            font-weight: 500;
            color: hsl(var(--space-text-muted));
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        .status-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: hsl(var(--glow-green));
            box-shadow: 0 0 8px hsl(var(--glow-green) / 0.5);
            animation: pulse 2.5s ease-in-out infinite;
        }}
        .nav-cmd {{
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            font-size: 0.75rem;
            font-weight: 500;
            color: hsl(var(--glow-cyan));
            text-decoration: none;
            padding: 0.3125rem 0.625rem;
            border-radius: calc(var(--radius) * 0.75);
            border: 1px solid hsl(var(--glow-cyan) / 0.15);
            transition: all 0.2s;
        }}
        .nav-cmd:hover {{
            background: hsl(var(--glow-cyan) / 0.08);
            border-color: hsl(var(--glow-cyan) / 0.3);
        }}
        .nav-cmd svg {{ opacity: 0.7; }}
        .hud-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .user-info {{
            font-size: 0.8125rem;
            color: hsl(var(--space-text-muted));
        }}
        .user-info strong {{
            color: hsl(var(--space-text));
            font-weight: 600;
        }}
        .btn-logout {{
            font-family: inherit;
            font-size: 0.75rem;
            font-weight: 500;
            color: hsl(var(--space-text-dim));
            background: transparent;
            border: 1px solid hsl(var(--space-border) / 0.5);
            border-radius: calc(var(--radius) * 0.75);
            padding: 0.3125rem 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
            letter-spacing: 0.02em;
        }}
        .btn-logout:hover {{
            color: hsl(0 70% 65%);
            border-color: hsl(0 70% 60% / 0.25);
            background: hsl(0 70% 60% / 0.06);
        }}

        /* ── Main Content ───────────────────────── */
        .main {{
            position: relative;
            z-index: 10;
            max-width: 980px;
            margin: 0 auto;
            padding: 3rem 1.5rem 2rem;
        }}
        .greeting {{
            margin-bottom: 2.5rem;
            animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both;
        }}
        .greeting-time {{
            font-size: 0.8125rem;
            font-weight: 500;
            color: hsl(var(--glow-cyan));
            letter-spacing: 0.04em;
            margin-bottom: 0.375rem;
        }}
        .page-title {{
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.035em;
            color: hsl(var(--space-text));
            margin-bottom: 0.375rem;
        }}
        .page-subtitle {{
            font-size: 0.875rem;
            color: hsl(var(--space-text-muted));
            font-weight: 400;
        }}

        /* ── App Grid & Cards ───────────────────── */
        .app-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 0.875rem;
        }}
        .app-card {{
            position: relative;
            z-index: 10;
            background: hsl(var(--space-surface) / 0.65);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid hsl(var(--space-border) / 0.5);
            border-radius: var(--radius);
            padding: 1.125rem 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.875rem;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            text-decoration: none;
            color: inherit;
            animation: cardIn 0.55s cubic-bezier(0.16, 1, 0.3, 1) both;
            animation-delay: calc(var(--i, 0) * 0.07s + 0.35s);
        }}
        .app-card:hover {{
            transform: translateY(-2px);
            border-color: hsl(var(--space-border) / 0.8);
            box-shadow: 0 4px 24px hsl(var(--space-deep) / 0.5);
        }}
        .app-card-link {{
            cursor: pointer;
        }}
        .app-card-link:hover {{
            border-color: hsl(var(--glow-cyan) / 0.3);
            box-shadow: 0 4px 24px hsl(var(--glow-cyan) / 0.08);
        }}

        /* ── Orbs ───────────────────────────────── */
        .app-orb {{
            width: 42px;
            height: 42px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            transition: box-shadow 0.3s;
        }}
        .app-orb span {{
            font-size: 1rem;
            font-weight: 700;
            color: white;
        }}
        .orb-oidc {{
            background: linear-gradient(135deg, hsl(var(--glow-blue)), hsl(var(--glow-cyan)));
            box-shadow: 0 0 16px hsl(var(--glow-cyan) / 0.25);
        }}
        .orb-saml {{
            background: linear-gradient(135deg, hsl(152 60% 35%), hsl(var(--glow-green)));
            box-shadow: 0 0 16px hsl(var(--glow-green) / 0.25);
        }}
        .orb-bookmark {{
            background: linear-gradient(135deg, hsl(28 80% 45%), hsl(var(--glow-amber)));
            box-shadow: 0 0 16px hsl(var(--glow-amber) / 0.2);
        }}
        .app-card:hover .orb-oidc {{ box-shadow: 0 0 24px hsl(var(--glow-cyan) / 0.4); }}
        .app-card:hover .orb-saml {{ box-shadow: 0 0 24px hsl(var(--glow-green) / 0.4); }}
        .app-card:hover .orb-bookmark {{ box-shadow: 0 0 24px hsl(var(--glow-amber) / 0.35); }}

        /* ── App Info ───────────────────────────── */
        .app-info {{
            flex: 1;
            min-width: 0;
        }}
        .app-name {{
            font-weight: 600;
            font-size: 0.9375rem;
            margin-bottom: 0.25rem;
            color: hsl(var(--space-text));
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        /* ── Badges ─────────────────────────────── */
        .badge {{
            display: inline-block;
            padding: 0.0625rem 0.4375rem;
            font-size: 0.625rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        .badge-oidc {{
            background: hsl(var(--glow-cyan) / 0.12);
            color: hsl(var(--glow-cyan));
        }}
        .badge-saml {{
            background: hsl(var(--glow-green) / 0.12);
            color: hsl(var(--glow-green));
        }}
        .badge-bookmark {{
            background: hsl(var(--glow-amber) / 0.12);
            color: hsl(var(--glow-amber));
        }}

        /* ── SSO Tag & Launch Icon ──────────────── */
        .sso-tag {{
            display: flex;
            align-items: center;
            gap: 0.375rem;
            font-size: 0.625rem;
            font-weight: 600;
            color: hsl(var(--space-text-dim));
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}
        .sso-dot {{
            width: 5px;
            height: 5px;
            border-radius: 50%;
            background: hsl(var(--glow-green));
            box-shadow: 0 0 6px hsl(var(--glow-green) / 0.4);
        }}
        .launch-icon {{
            width: 18px;
            height: 18px;
            color: hsl(var(--space-text-dim));
            flex-shrink: 0;
            transition: all 0.25s;
        }}
        .app-card-link:hover .launch-icon {{
            color: hsl(var(--glow-cyan));
            transform: translate(2px, -2px);
        }}

        /* ── Empty State ────────────────────────── */
        .empty-state {{
            text-align: center;
            padding: 5rem 2rem;
            animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.3s both;
        }}
        .empty-rings {{
            position: relative;
            width: 120px;
            height: 120px;
            margin: 0 auto 2rem;
        }}
        .ring {{
            position: absolute;
            border: 1px solid hsl(var(--glow-cyan) / 0.1);
            border-radius: 50%;
            top: 50%;
            left: 50%;
        }}
        .ring-1 {{
            width: 60px; height: 60px;
            animation: ringPulse 3s ease-in-out infinite;
        }}
        .ring-2 {{
            width: 90px; height: 90px;
            animation: ringPulse 3s ease-in-out 0.5s infinite;
        }}
        .ring-3 {{
            width: 120px; height: 120px;
            animation: ringPulse 3s ease-in-out 1s infinite;
        }}
        .ring-dot {{
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            width: 8px; height: 8px;
            border-radius: 50%;
            background: hsl(var(--glow-cyan));
            box-shadow: 0 0 12px hsl(var(--glow-cyan) / 0.4);
        }}
        .empty-title {{
            font-size: 1rem;
            font-weight: 600;
            color: hsl(var(--space-text-muted));
            margin-bottom: 0.375rem;
        }}
        .empty-desc {{
            font-size: 0.8125rem;
            color: hsl(var(--space-text-dim));
            max-width: 300px;
            margin: 0 auto;
            line-height: 1.5;
        }}

        /* ── Footer ─────────────────────────────── */
        .footer {{
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 3rem 2rem 2rem;
            font-size: 0.6875rem;
            color: hsl(var(--space-text-muted) / 0.3);
        }}
        .footer a {{
            color: inherit;
            text-decoration: none;
            transition: color 0.2s;
        }}
        .footer a:hover {{
            color: hsl(var(--space-text-muted));
        }}
        .version {{
            margin-top: 0.375rem;
            font-size: 0.625rem;
            opacity: 0.5;
        }}

        /* ── Responsive ─────────────────────────── */
        @media (max-width: 640px) {{
            .hud {{ padding: 0.625rem 1rem; }}
            .status {{ display: none; }}
            .main {{ padding: 2rem 1rem 1.5rem; }}
            .page-title {{ font-size: 1.5rem; }}
            .app-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <canvas id="stars"></canvas>
    <div class="bg-nebula"></div>
    <div class="bg-grid"></div>
    <div class="shooting-star ss-1"></div>
    <div class="shooting-star ss-2"></div>
    <div class="shooting-star ss-3"></div>

    <header class="hud">
        <div class="hud-left">
            <span class="brand">Houston</span>
            <div class="status"><span class="status-dot"></span>Systems Nominal</div>
            {admin_link}
        </div>
        <div class="hud-right">
            <span class="user-info">Signed in as <strong>{display_name}</strong></span>
            <form method="POST" action="/logout" style="margin:0">
                <button type="submit" class="btn-logout">Sign Out</button>
            </form>
        </div>
    </header>

    <main class="main">
        <div class="greeting">
            <p class="greeting-time"><span id="greeting-time">Welcome</span>, {greeting_name}</p>
            <h1 class="page-title">Launch Pad</h1>
            <p class="page-subtitle">{app_count_text}</p>
        </div>
        {cards_html}
    </main>

    <footer class="footer">
        <a href="https://github.com/shawntz/houston" target="_blank">&copy; Shawn Schwartz 2026 &mdash; All Rights Reserved.</a>
        <div class="version">v{version}</div>
    </footer>

    <script>
        (function() {{
            var c = document.getElementById('stars');
            var ctx = c.getContext('2d');
            var w, h;
            var stars = [];
            function resize() {{
                w = c.width = window.innerWidth;
                h = c.height = window.innerHeight;
            }}
            function init() {{
                resize();
                for (var i = 0; i < 180; i++) {{
                    stars.push({{
                        x: Math.random() * w,
                        y: Math.random() * h,
                        r: Math.random() * 1.2 + 0.3,
                        a: Math.random() * 0.7 + 0.1
                    }});
                }}
            }}
            function draw() {{
                ctx.clearRect(0, 0, w, h);
                for (var i = 0; i < stars.length; i++) {{
                    var s = stars[i];
                    s.a += (Math.random() - 0.5) * 0.01;
                    if (s.a < 0.05) s.a = 0.05;
                    if (s.a > 0.85) s.a = 0.85;
                    ctx.beginPath();
                    ctx.arc(s.x, s.y, s.r, 0, 6.283);
                    ctx.fillStyle = 'rgba(255,255,255,' + s.a + ')';
                    ctx.fill();
                }}
                requestAnimationFrame(draw);
            }}
            window.addEventListener('resize', resize);
            init();
            draw();

            var hour = new Date().getHours();
            var g = hour < 5 ? 'Night watch' : hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
            var el = document.getElementById('greeting-time');
            if (el) el.textContent = g;
        }})();
    </script>
</body>
</html>"#,
        admin_link = admin_link,
        display_name = display_name,
        greeting_name = greeting_name,
        app_count_text = app_count_text,
        cards_html = cards_html,
        version = env!("CARGO_PKG_VERSION"),
    );

    Html(html).into_response()
}
