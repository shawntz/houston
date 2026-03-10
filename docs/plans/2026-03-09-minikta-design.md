# minikta — Minimal Self-Hosted Identity Provider

## Overview

A self-hosted, open-source alternative to Okta built in Rust. Single binary deployment with embedded SQLite and admin UI. Supports OIDC/OAuth 2.0 (for custom apps) and SAML 2.0 (for third-party SaaS). Authentication via password + TOTP and passkeys/WebAuthn.

**Target**: Personal use / small scale (< 10 users).

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   minikta                        │
│                                                  │
│  ┌───────────┐  ┌───────────┐  ┌─────────────┐  │
│  │  OIDC     │  │  SAML     │  │  Admin API  │  │
│  │  Provider  │  │  IdP      │  │  (REST)     │  │
│  └─────┬─────┘  └─────┬─────┘  └──────┬──────┘  │
│        │              │               │          │
│  ┌─────▼──────────────▼───────────────▼──────┐  │
│  │           Core Auth Engine                 │  │
│  │  (sessions, password, TOTP, WebAuthn)      │  │
│  └─────────────────┬──────────────────────────┘  │
│                    │                             │
│  ┌─────────────────▼──────────────────────────┐  │
│  │           SQLite (rusqlite)                 │  │
│  │  users, credentials, apps, sessions, logs  │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Embedded Admin SPA (Svelte, static assets)│  │
│  └────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

**Key principles**:
- Single process, single binary — SQLite embedded, admin UI assets embedded via `rust-embed`
- Three protocol surfaces: OIDC provider endpoints, SAML IdP endpoints, REST admin API
- One shared auth engine — all login flows go through the same core regardless of protocol
- Config via `config.toml` with env var overrides (`MINIKTA_*`)

## Data Model

### users
| Column | Type | Notes |
|--------|------|-------|
| id | UUID, PK | |
| username | TEXT, UNIQUE, NOT NULL | |
| email | TEXT, UNIQUE, NOT NULL | |
| display_name | TEXT | |
| password_hash | TEXT | argon2id |
| totp_secret | BLOB, nullable | AES-256-GCM encrypted at rest |
| is_admin | BOOLEAN | |
| created_at | TIMESTAMP | |
| updated_at | TIMESTAMP | |

### webauthn_credentials
| Column | Type | Notes |
|--------|------|-------|
| id | UUID, PK | |
| user_id | FK → users | |
| credential_id | BLOB | From WebAuthn |
| public_key | BLOB | |
| sign_count | u32 | Replay/clone protection |
| name | TEXT | User-friendly label |
| created_at | TIMESTAMP | |
| last_used_at | TIMESTAMP | |

### apps (registered relying parties)
| Column | Type | Notes |
|--------|------|-------|
| id | UUID, PK | |
| name | TEXT | e.g. "GitHub", "My App" |
| protocol | ENUM | oidc or saml |
| client_id | TEXT, UNIQUE | OIDC only |
| client_secret_hash | TEXT, nullable | OIDC, argon2id (nullable for public clients) |
| redirect_uris | JSON | OIDC only |
| entity_id | TEXT | SAML SP entity ID |
| acs_url | TEXT | SAML Assertion Consumer Service URL |
| name_id_format | TEXT | SAML (e.g. emailAddress) |
| created_at | TIMESTAMP | |
| updated_at | TIMESTAMP | |

### sessions
| Column | Type | Notes |
|--------|------|-------|
| id | UUID, PK | |
| user_id | FK → users | |
| token_hash | TEXT | SHA-256 of session cookie (never stored raw) |
| ip_address | TEXT | |
| user_agent | TEXT | |
| created_at | TIMESTAMP | |
| expires_at | TIMESTAMP | |
| last_active_at | TIMESTAMP | |

### authorization_codes
| Column | Type | Notes |
|--------|------|-------|
| code_hash | TEXT, PK | SHA-256 (never stored raw) |
| user_id | FK → users | |
| app_id | FK → apps | |
| redirect_uri | TEXT | |
| scopes | JSON | |
| code_challenge | TEXT | PKCE, required |
| expires_at | TIMESTAMP | 60 seconds |
| created_at | TIMESTAMP | |

### audit_log
| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER, autoincrement | |
| timestamp | TIMESTAMP | |
| user_id | FK → users, nullable | |
| action | TEXT | e.g. "login_success", "app_created" |
| ip_address | TEXT | |
| detail | JSON | Flexible context |
| app_id | FK → apps, nullable | |

**Append-only**: no UPDATE/DELETE on audit_log.

## Authentication Flows

### Shared Login Flow

1. OIDC `/oauth/authorize` or SAML `/saml/sso` redirects to login if no session exists
2. Session cookie checked (hash lookup). If valid session → skip to protocol response
3. Step 1: Username + Password OR Passkey
4. Step 2 (password path only): TOTP if enrolled
5. Passkey path: no second factor needed (inherently multi-factor)
6. Create session, set HttpOnly/Secure/SameSite=Lax cookie
7. Issue OIDC auth code (redirect with `?code=`) or SAML Response (POST to ACS URL)

### OIDC Token Endpoint
- Exchanges authorization code for `id_token` (JWT, Ed25519) + `access_token`
- Validates PKCE `code_verifier`
- Standard claims: `sub`, `email`, `name`, `iss`, `aud`, `exp`
- Public keys at `/.well-known/jwks.json`

### SAML Response
- `<saml:Assertion>` with NameID and attributes
- Signed with XML-DSig (RSA-SHA256)
- Auto-POSTed to SP's ACS URL

## API Endpoints

### Protocol (public)
- `GET /.well-known/openid-configuration` — OIDC discovery
- `GET /.well-known/jwks.json` — Public signing keys
- `GET /oauth/authorize` — Authorization endpoint
- `POST /oauth/token` — Token exchange
- `GET /oauth/userinfo` — User info
- `GET /saml/metadata` — IdP metadata XML
- `GET|POST /saml/sso` — SAML SSO (Redirect + POST bindings)

### Login UI
- `GET /login` — Login page
- `POST /login/password` — Username + password
- `POST /login/totp` — TOTP code
- `POST /login/webauthn/challenge` — WebAuthn challenge
- `POST /login/webauthn/verify` — WebAuthn assertion
- `POST /logout` — Destroy session

### Admin REST API (requires is_admin)
- `CRUD /api/admin/users` — User management
- `CRUD /api/admin/apps` — App registration
- `POST /api/admin/apps/:id/rotate-secret` — Rotate OIDC client secret
- `GET /api/admin/sessions` + `DELETE /api/admin/sessions/:id` — Session management
- `GET /api/admin/audit-log` — Query audit log

### Admin Dashboard (embedded SPA)
- `GET /admin/*` — Svelte SPA served via rust-embed
- Pages: Dashboard, Users, Apps, Sessions, Audit Log

### CLI
- `minikta init` — Create initial admin user
- `minikta serve` — Start server
- `minikta generate-keys` — Regenerate signing keys

## Security Model

### Signing Keys
- OIDC: **Ed25519** for JWT signing
- SAML: **RSA-SHA256** (2048-bit) for XML-DSig
- Generated on `minikta init`, stored encrypted at rest

### Master Secret
Single `master_secret` in config, derived via HKDF-SHA256:
- `HKDF(info="totp-encryption")` → AES key for TOTP secrets
- `HKDF(info="key-encryption")` → AES key for private keys
- `HKDF(info="csrf-tokens")` → HMAC key for CSRF tokens

### Password Policy
- argon2id (19 MiB, 2 iterations, 1 parallelism)
- Minimum 12 characters
- HaveIBeenPwned k-anonymity check on creation/change

### Session Security
- HttpOnly, Secure, SameSite=Lax cookies
- 8-hour sliding window, configurable absolute maximum
- Token hashes only stored in DB
- Bound to User-Agent

### CSRF
- HMAC-SHA256(session_id + timestamp) tokens on all state-changing POSTs

### Rate Limiting
- Login: 5 failures/username/15min, exponential backoff
- Token endpoint: 20 req/client_id/min
- Admin API: 100 req/min
- In-process token bucket

### TLS
- HTTP only — TLS terminated by reverse proxy (Caddy/nginx)
- `require_https: true` default (checks X-Forwarded-Proto)

## Crate Dependencies

| Purpose | Crate |
|---------|-------|
| HTTP | axum |
| Runtime | tokio |
| Database | rusqlite + deadpool-sqlite |
| Migrations | refinery |
| OIDC | openidconnect |
| JWT | jsonwebtoken |
| SAML | samael |
| XML | quick-xml |
| Passwords | argon2 |
| TOTP | totp-rs |
| WebAuthn | webauthn-rs |
| Crypto | ring |
| Serialization | serde + serde_json |
| Config | config |
| Embedded assets | rust-embed |
| Logging | tracing + tracing-subscriber |
| CLI | clap |
| Errors | thiserror + anyhow |

## Project Structure

```
minikta/
├── Cargo.toml
├── config.example.toml
├── Dockerfile
├── migrations/
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── db/          (users, apps, sessions, credentials, audit)
│   ├── auth/        (password, totp, webauthn, session)
│   ├── crypto/      (keys, hkdf)
│   ├── oidc/        (discovery, authorize, token, userinfo)
│   ├── saml/        (metadata, sso)
│   ├── admin/       (users, apps, sessions, audit REST endpoints)
│   ├── middleware/   (auth, csrf, rate_limit)
│   └── web/         (login page rendering + form handlers)
├── admin-ui/        (Svelte SPA)
└── tests/integration/
```

## Testing Strategy

- **Unit**: Crypto ops, hashing, TOTP, token bucket, CSRF in each module
- **Integration**: Full OIDC flow, full SAML flow, login flows, admin API CRUD (in-memory SQLite)
- **E2E**: Real OIDC client + SAML test SP against a running instance

## Error Handling

- External: generic messages ("invalid credentials"), no internal state leakage
- Internal: structured tracing logs with full context
- Timing-safe: identical response for "user not found" vs "wrong password" (dummy argon2id verify)
- Fail closed: verification errors → reject, never skip
- All errors → audit log
- No `.unwrap()` in production paths; `Result<T, E>` with thiserror enums throughout
