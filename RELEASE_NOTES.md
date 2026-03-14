# Houston v0.2.0 Release Notes

Houston is a self-hosted identity provider — a minimal, open-source alternative to Okta. Single Rust binary with embedded SQLite and a Svelte 5 admin dashboard.

## Highlights

Houston ships with full OIDC/OAuth 2.0 and SAML 2.0 support, a polished admin dashboard, passwordless login via passkeys, and a space-themed end-user app launcher.

### New in v0.2.0

- **App Drawer / Launch Pad**: End-user dashboard at `/` showing all assigned applications as a card grid. Space-themed dark UI with canvas starfield, glassmorphism cards, and protocol-colored orbs. Time-aware greeting, staggered card animations, and HUD-style navigation.
- **Bookmark Apps**: New `bookmark` protocol type — a simple name + URL with no SSO config. Bookmark cards link directly to external URLs. Registered and managed alongside OIDC/SAML apps in the admin dashboard.
- **App Icons**: Optional icon URL per application — paste any image URL and the launcher shows the app logo in place of the default initial-letter orb.
- **Launch URL Templates**: Configurable launch URL with variable substitution (`{{email}}`, `{{username}}`, `{{name}}`). Enables pre-filled login flows — e.g., `https://notion.so/login?email={{email}}` auto-populates the user's email on the target app's login page.
- **App Settings Panel**: Inline settings editor in the admin dashboard for updating icon and launch URL on existing apps (`PUT /api/admin/apps/{id}`).
- **Clickable App Cards**: All app cards in the launcher are now clickable links — OIDC cards link to the app origin (derived from redirect URI), SAML cards link to the ACS origin, and bookmark cards link directly to their URL. Launch URL overrides all when configured.
- **Post-Login Redirect**: Login now redirects to `/` (the app launcher) instead of `/admin`, giving all users a landing page — not just admins.

## Identity Protocols

- **OIDC/OAuth 2.0**: Authorization code flow with mandatory PKCE, JWT access & ID tokens (Ed25519-signed), discovery endpoint (`/.well-known/openid-configuration`), JWKS endpoint, token endpoint with `authorization_code` grant, userinfo endpoint
- **SAML 2.0**: HTTP-Redirect binding for AuthnRequest, HTTP-POST binding for signed Response, RSA-SHA256 XML digital signatures (enveloped), IdP metadata endpoint with signing certificate, auto-submit POST form for seamless SSO
- **Bookmark**: External URL links — no SSO configuration, just a name and target URL displayed in the user's app launcher
- All protocols support optional **icon URL** (app logo) and **launch URL** (template with user variable substitution)

## Authentication

- **Password**: Argon2id hashing with timing-safe dummy verify to prevent username enumeration
- **Passkeys/WebAuthn**: Full registration and authentication flows using webauthn-rs, Touch ID / YubiKey / platform authenticator support, counter tracking and credential naming
- **TOTP**: Secret generation and verification (enrollment flow pending)
- **Session management**: Random 32-byte tokens, SHA-256 hashed in DB, configurable TTL

## Security

- Single `master_secret` derives all keys via HKDF-SHA256 (CSRF, TOTP encryption, key encryption)
- Ed25519 keypair for JWT signing, RSA-2048 keypair for SAML signing
- Private keys encrypted at rest with AES-256-GCM
- CSRF protection on state-changing operations
- In-process token bucket rate limiter on login
- PKCE required for all OIDC flows (S256 only)
- Session tokens stored as SHA-256 hashes only

## User-App Assignments

- Applications are unassigned by default — users must be explicitly granted access
- Enforcement at both OIDC authorization and SAML SSO boundaries
- Styled access-denied page for SAML, error redirect for OIDC
- Admin API and UI for managing assignments per app

## Admin Dashboard

- **Svelte 5 SPA** embedded into the binary via rust-embed (zero external files to deploy)
- Shadcn-style design system with HSL custom properties
- Hash-based client-side routing
- Pages: Dashboard, Users, Apps, Sessions, Audit Log
- User management: create, edit, delete, passkey registration
- App management: register OIDC/SAML/Bookmark apps, rotate client IDs, manage user assignments, configure icon and launch URL via inline settings panel
- Session viewer with revocation
- Audit log with action/user filtering

## End-User UI

- **App Launcher (Launch Pad)**: Server-rendered dashboard at `/` with assigned apps as a card grid. Canvas-based starfield with twinkling stars, CSS nebula gradients, shooting star animations, frosted-glass header with scan-line effect, protocol-colored glowing orbs (or custom app icons), staggered card entrance animations, pulsing radar empty state, time-aware greeting, clickable cards with launch URL template support, and responsive layout.
- **Login page**: Animated login page with loading spinner and success overlay, passkey authentication with "or continue with" flow, branded header ("Houston SSO — Ready for Launch..."), version display in footer

## Infrastructure

- **Single binary**: All assets compiled in, deploy anywhere
- **SQLite**: Embedded database with WAL mode, automatic migrations via refinery
- **Config**: TOML file + environment variable overrides (`HOUSTON__` prefix)
- **Docker**: Multi-stage Dockerfile for minimal production image
- **CLI**: `houston init` (DB + admin user), `houston serve`, `houston generate-keys`
- **CI**: GitHub Actions workflow with Rust build, test, and admin UI build

## Version Display

- `Cargo.toml` version rendered on login page, app launcher, admin sidebar, and access-denied pages
- `/api/admin/version` endpoint for programmatic access

## Stats

- 83 tests (70 unit + 13 integration)
- ~6,000 lines of Rust, ~1,200 lines of Svelte/TypeScript
