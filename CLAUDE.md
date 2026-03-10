# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Houston is a self-hosted identity provider (Okta alternative) built in Rust. Single binary with embedded SQLite and a Svelte 5 admin dashboard. Supports OIDC/OAuth 2.0 and SAML 2.0.

## Build & Run

```bash
# Build admin UI first (assets are embedded into the Rust binary via rust-embed)
cd admin-ui && npm install && npm run build && cd ..

# Build Rust binary
cargo build --release

# Initialize DB + admin user
./target/release/houston init --admin-username admin --admin-email you@example.com

# Start server
./target/release/houston serve --config config.toml
```

## Testing

```bash
cargo test                           # All 71 tests (60 unit + 11 integration)
cargo test test_name                 # Single test by name
cargo test --test admin_api          # Single integration test file
cargo test auth::password            # Tests in a specific module
```

Unit tests are inline (`#[cfg(test)] mod tests`) in each module. Integration tests are in `tests/{admin_api.rs, oidc_flow.rs, saml_flow.rs}`.

Test helper: `houston::db::test_db()` creates an in-memory SQLite database with migrations applied. Integration tests build a full `AppState` with `AppConfig::default()` and use `tower::ServiceExt::oneshot()` to test routes without starting an HTTP server.

## Architecture

**Shared state**: `Arc<AppState>` holds config, `Mutex<Connection>` (SQLite), signing keys, rate limiter, CSRF key, and WebAuthn state. Injected via Axum's `State` extractor.

**Router composition** (`server.rs`): Each module exports a `routes() -> Router<Arc<AppState>>` function, merged in `build_router()`:
- `web::routes()` — `/login`, `/logout`, `/login/webauthn/*`
- `oidc::routes()` — `/.well-known/*`, `/oauth/*`
- `saml::routes()` — `/saml/*`
- `admin::routes()` — `/api/admin/*`, `/admin/*` (SPA)

**Auth middleware** (`middleware/auth.rs`): `AuthUser` and `RequireAdmin` are Axum `FromRequestParts` extractors. They read the session cookie, hash the token, look up the session in SQLite, and load the user. Use them as handler parameters:
```rust
async fn handler(RequireAdmin(user): RequireAdmin, State(state): State<Arc<AppState>>) -> impl IntoResponse { ... }
```

**Admin SPA** (`admin/spa.rs`): Built Svelte assets in `admin-ui/dist/` are compiled into the binary via `#[derive(Embed)]`. Vite is configured with `base: '/admin/'`. Unmatched paths under `/admin/*` fall back to `index.html` for client-side routing.

**Crypto strategy**: Single `master_secret` in config → HKDF-SHA256 derives all keys using info labels (`"csrf-tokens"`, `"totp-encryption"`, `"key-encryption"`). Ed25519 for JWT signing. RSA-SHA256 for SAML XML-DSig. AES-256-GCM for encrypting secrets at rest.

**Database**: SQLite via rusqlite. Migrations in `migrations/` using refinery. DAO functions in `db/{users,apps,sessions,audit}.rs` return domain structs. `db::test_db()` is public (not behind `#[cfg(test)]`) so integration tests can use it.

## Key Conventions

- Config loads from TOML file + env vars with `HOUSTON__` prefix (double underscore separator, e.g. `HOUSTON__SERVER__PORT=9090`)
- Default DB filename: `houston.db`, default cookie: `houston_session`
- Session tokens: random 32 bytes → SHA-256 hash stored in DB, plaintext in cookie
- PKCE is required for all OIDC flows
- Password hashing: argon2id with timing-safe dummy verify on invalid usernames
- Admin UI uses Svelte 5 runes (`$state()`, `$effect()`) and hash-based routing
- Admin UI design system: shadcn-style CSS custom properties (HSL tokens in `app.css`)
- The `samael` crate requires system libraries: `libxml2`, `libxmlsec1` (install via `brew install libxmlsec1 libxml2` on macOS)
