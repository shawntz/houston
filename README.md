# houston :rocket:

Self-hosted identity provider. OIDC + SAML 2.0 in a single binary.

Built to replace Okta for personal and small-team use (< 10 users) without the $$$ minimum annual contract.

## Features

- **OIDC/OAuth 2.0** — Authorization code flow with PKCE, discovery, JWKS
- **SAML 2.0** — IdP-initiated and SP-initiated SSO, metadata endpoint
- **Authentication** — Passwords (argon2id), TOTP, WebAuthn/passkeys
- **Admin dashboard** — Embedded Svelte SPA for managing users, apps, sessions, and audit logs
- **Single binary** — SQLite database and admin UI assets compiled in
- **Audit logging** — Append-only log of all authentication and admin events

## Architecture

```
Internet → Caddy/nginx (TLS) → houston (:8080)
                                  ├── OIDC endpoints    /.well-known/*, /oauth/*
                                  ├── SAML endpoints    /saml/*
                                  ├── Login UI          /login
                                  ├── Admin API         /api/admin/*
                                  └── Admin SPA         /admin/*
                                        ↕
                                    SQLite (embedded)
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Node.js 20+ (to build the admin UI)

### Build

```bash
# Build admin UI
cd admin-ui && npm install && npm run build && cd ..

# Build the binary
cargo build --release
```

### Configure

```bash
cp config.example.toml config.toml
```

Edit `config.toml`:

```toml
[server]
host = "127.0.0.1"
port = 8080
external_url = "https://auth.yourdomain.com"

[secrets]
master_secret = "generate-with-openssl-rand-hex-32"

[database]
path = "houston.db"
```

Generate a master secret:

```bash
openssl rand -hex 32
```

### Run

```bash
./target/release/houston --config config.toml
```

The admin dashboard is at `http://localhost:8080/admin`.

## Deployment

houston is designed to sit behind a reverse proxy that handles TLS. Here's a minimal Caddy setup:

```
# /etc/caddy/Caddyfile
auth.yourdomain.com {
    reverse_proxy localhost:8080
}
```

Caddy automatically provisions Let's Encrypt certificates.

### systemd

```ini
[Unit]
Description=houston identity provider
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/houston --config /etc/houston/config.toml
WorkingDirectory=/var/lib/houston
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/houston

[Install]
WantedBy=multi-user.target
```

## Connecting Apps

### OIDC

1. Register an app in the admin dashboard (Apps → Register App → OIDC)
2. Note the `client_id` and configure your redirect URI
3. Point your app at these endpoints:
   - Discovery: `https://auth.yourdomain.com/.well-known/openid-configuration`
   - Authorization: `https://auth.yourdomain.com/oauth/authorize`
   - Token: `https://auth.yourdomain.com/oauth/token`
   - JWKS: `https://auth.yourdomain.com/.well-known/jwks.json`

PKCE is required for all flows.

### SAML

1. Register an app in the admin dashboard (Apps → Register App → SAML)
2. Provide the SP's Entity ID and ACS URL
3. Give the SP your IdP metadata: `https://auth.yourdomain.com/saml/metadata`

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public signing keys |
| `GET /oauth/authorize` | OIDC authorization |
| `POST /oauth/token` | OIDC token exchange |
| `GET /saml/metadata` | SAML IdP metadata |
| `GET /saml/sso` | SAML SSO (redirect binding) |
| `GET /login` | Login page |
| `GET /admin` | Admin dashboard |
| `* /api/admin/*` | Admin REST API (requires admin session) |

## Configuration Reference

See [`config.example.toml`](config.example.toml) for all options.

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `server` | `host` | `127.0.0.1` | Bind address |
| `server` | `port` | `8080` | Bind port |
| `server` | `external_url` | — | Public URL (used in metadata/discovery) |
| `secrets` | `master_secret` | — | HKDF master key for all derived secrets |
| `database` | `path` | `houston.db` | SQLite database file path |
| `session` | `ttl_seconds` | `28800` | Session TTL (8 hours) |
| `session` | `cookie_name` | `houston_session` | Session cookie name |
| `rate_limit` | `login_max_attempts` | `5` | Max login failures per 15 min |
| `password` | `min_length` | `12` | Minimum password length |
| `password` | `check_hibp` | `true` | Check HaveIBeenPwned on password set |

## Security

- **Passwords**: argon2id (19 MiB, 2 iterations)
- **Sessions**: SHA-256 hashed tokens, HttpOnly/Secure/SameSite=Lax cookies
- **OIDC signing**: Ed25519 (JWTs)
- **SAML signing**: RSA-SHA256 (XML-DSig)
- **Key derivation**: HKDF-SHA256 from a single master secret
- **Rate limiting**: In-process token bucket on login and token endpoints
- **CSRF**: HMAC-SHA256 tokens on all state-changing forms
- **Timing-safe**: Dummy argon2id verify on invalid usernames to prevent user enumeration

## Tech Stack

- **Rust** — axum, tokio, rusqlite
- **SQLite** — Embedded, single-file database
- **Svelte 5** — Admin dashboard SPA, embedded via rust-embed
- **Caddy** — Recommended reverse proxy for automatic TLS

## Development

```bash
# Run tests (60 unit + 11 integration)
cargo test

# Run with live admin UI reload
cd admin-ui && npm run dev    # terminal 1
cargo run -- --config config.toml  # terminal 2
```

## License

MIT
