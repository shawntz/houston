# minikta Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a self-hosted identity provider in Rust with OIDC, SAML, password/TOTP/WebAuthn auth, SQLite storage, and an embedded Svelte admin dashboard — deployable as a single binary.

**Architecture:** Axum HTTP framework with a layered architecture: protocol endpoints (OIDC/SAML) → shared auth engine → SQLite via rusqlite. Admin SPA embedded into the binary via rust-embed. Config via TOML + env vars.

**Tech Stack:** Rust (axum, tokio, rusqlite, samael, openidconnect, webauthn-rs, argon2, ring), Svelte (admin UI), SQLite

**Design doc:** `docs/plans/2026-03-09-minikta-design.md`

---

## Phase 1: Project Scaffold & Config

### Task 1: Initialize Cargo project and dependencies

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `config.example.toml`
- Create: `.gitignore`

**Step 1: Create Cargo.toml with all dependencies**

```toml
[package]
name = "minikta"
version = "0.1.0"
edition = "2021"
description = "Minimal self-hosted identity provider with OIDC and SAML support"

[dependencies]
# HTTP & async
axum = { version = "0.8", features = ["macros"] }
axum-extra = { version = "0.10", features = ["cookie", "typed-header"] }
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "fs", "trace"] }

# Database
rusqlite = { version = "0.32", features = ["bundled", "uuid"] }
deadpool = "0.12"
refinery = { version = "0.8", features = ["rusqlite"] }

# OIDC / JWT
jsonwebtoken = "9"

# SAML
samael = { version = "0.0.17", features = ["xmlsec"] }
quick-xml = "0.37"

# Auth
argon2 = "0.5"
totp-rs = { version = "5", features = ["qr", "gen_secret"] }
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
webauthn-rs-proto = "0.5"

# Crypto
ring = "0.17"
base64 = "0.22"
rand = "0.8"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Config
config = "0.14"

# Embedded assets
rust-embed = { version = "8", features = ["mime-guess"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Error handling
thiserror = "2"
anyhow = "1"

# Misc
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
url = { version = "2", features = ["serde"] }
hex = "0.4"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json", "cookies"] }
tower = { version = "0.5", features = ["util"] }
http-body-util = "0.1"
tempfile = "3"
```

**Step 2: Create minimal src/main.rs**

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "minikta", about = "Minimal self-hosted identity provider")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the database and create an admin user
    Init {
        #[arg(long)]
        admin_username: String,
        #[arg(long)]
        admin_email: String,
    },
    /// Start the server
    Serve {
        #[arg(long, default_value = "config.toml")]
        config: String,
    },
    /// Regenerate signing keys
    GenerateKeys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { admin_username, admin_email } => {
            println!("Initializing minikta with admin user: {admin_username} <{admin_email}>");
            todo!("init command")
        }
        Commands::Serve { config } => {
            println!("Starting minikta with config: {config}");
            todo!("serve command")
        }
        Commands::GenerateKeys => {
            println!("Regenerating signing keys...");
            todo!("generate-keys command")
        }
    }
}
```

**Step 3: Create config.example.toml**

```toml
# minikta configuration
# Copy to config.toml and edit.

[server]
# Address to bind to
host = "127.0.0.1"
port = 8080
# External URL (used in OIDC discovery, SAML metadata)
external_url = "https://id.example.com"
# Require HTTPS via X-Forwarded-Proto header
require_https = true

[secrets]
# Master secret for key derivation (HKDF). Generate with: openssl rand -hex 32
master_secret = "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32"

[database]
# Path to SQLite database file
path = "minikta.db"

[session]
# Session TTL in seconds (default: 8 hours)
ttl_seconds = 28800
# Absolute maximum session lifetime in seconds (default: 24 hours)
max_lifetime_seconds = 86400
# Cookie name
cookie_name = "minikta_session"

[rate_limit]
# Max login failures per username per window
login_max_attempts = 5
# Window in seconds
login_window_seconds = 900

[password]
# Minimum password length
min_length = 12
# Check passwords against HaveIBeenPwned (k-anonymity API)
check_hibp = true
```

**Step 4: Create .gitignore**

```
/target
minikta.db
minikta.db-journal
minikta.db-wal
config.toml
keys/
admin-ui/node_modules/
admin-ui/dist/
*.pem
```

**Step 5: Verify it compiles**

Run: `cargo check`
Expected: Compiles successfully (with unused warnings, that's fine)

**Step 6: Commit**

```bash
git add Cargo.toml src/main.rs config.example.toml .gitignore
git commit -m "feat: initialize minikta project scaffold"
```

---

### Task 2: Config module

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs`
- Test: `src/config.rs` (inline tests)

**Step 1: Write the failing test**

In `src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_config_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        write!(f, r#"
[server]
host = "0.0.0.0"
port = 9090
external_url = "https://id.test.com"
require_https = false

[secrets]
master_secret = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

[database]
path = "test.db"

[session]
ttl_seconds = 3600
max_lifetime_seconds = 7200
cookie_name = "test_session"

[rate_limit]
login_max_attempts = 3
login_window_seconds = 600

[password]
min_length = 8
check_hibp = false
"#).unwrap();

        let cfg = AppConfig::load(config_path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.port, 9090);
        assert_eq!(cfg.server.external_url, "https://id.test.com");
        assert!(!cfg.server.require_https);
        assert_eq!(cfg.session.ttl_seconds, 3600);
        assert_eq!(cfg.password.min_length, 8);
    }

    #[test]
    fn test_config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        write!(f, r#"
[server]
external_url = "https://id.test.com"

[secrets]
master_secret = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
"#).unwrap();

        let cfg = AppConfig::load(config_path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.server.port, 8080);
        assert!(cfg.server.require_https);
        assert_eq!(cfg.session.ttl_seconds, 28800);
        assert_eq!(cfg.password.min_length, 12);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib config`
Expected: FAIL — `AppConfig` not defined

**Step 3: Write implementation**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub password: PasswordConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub external_url: String,
    #[serde(default = "default_true")]
    pub require_https: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecretsConfig {
    pub master_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { path: default_db_path() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_session_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_session_max")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_session_ttl(),
            max_lifetime_seconds: default_session_max(),
            cookie_name: default_cookie_name(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_login_max")]
    pub login_max_attempts: u32,
    #[serde(default = "default_login_window")]
    pub login_window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_max_attempts: default_login_max(),
            login_window_seconds: default_login_window(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordConfig {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_true")]
    pub check_hibp: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            check_hibp: default_true(),
        }
    }
}

fn default_host() -> String { "127.0.0.1".to_string() }
fn default_port() -> u16 { 8080 }
fn default_true() -> bool { true }
fn default_db_path() -> String { "minikta.db".to_string() }
fn default_session_ttl() -> u64 { 28800 }
fn default_session_max() -> u64 { 86400 }
fn default_cookie_name() -> String { "minikta_session".to_string() }
fn default_login_max() -> u32 { 5 }
fn default_login_window() -> u64 { 900 }
fn default_min_length() -> usize { 12 }

impl AppConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("MINIKTA").separator("__"))
            .build()?;

        let cfg: AppConfig = settings.try_deserialize()?;
        Ok(cfg)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --lib config`
Expected: PASS

**Step 5: Wire config into main.rs**

Add `mod config;` to `main.rs`. Update the `Serve` command to load config:

```rust
Commands::Serve { config: config_path } => {
    let _cfg = crate::config::AppConfig::load(&config_path)?;
    println!("Config loaded. Starting server on {}:{}", _cfg.server.host, _cfg.server.port);
    todo!("serve command")
}
```

**Step 6: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "feat: add config module with TOML + env var loading"
```

---

## Phase 2: Database Layer

### Task 3: SQLite connection pool and migrations

**Files:**
- Create: `src/db/mod.rs`
- Create: `migrations/V001__initial_schema.sql`
- Modify: `src/main.rs`

**Step 1: Create the migration SQL**

`migrations/V001__initial_schema.sql`:

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    totp_secret BLOB,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT 'Security Key',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at TEXT
);

CREATE TABLE apps (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    -- OIDC fields
    client_id TEXT UNIQUE,
    client_secret_hash TEXT,
    redirect_uris TEXT, -- JSON array
    -- SAML fields
    entity_id TEXT,
    acs_url TEXT,
    name_id_format TEXT DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL,
    last_active_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE authorization_codes (
    code_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]', -- JSON array
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}', -- JSON
    app_id TEXT REFERENCES apps(id) ON DELETE SET NULL
);

CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_apps_client_id ON apps(client_id);
CREATE INDEX idx_apps_entity_id ON apps(entity_id);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
```

**Step 2: Create db module with pool and migration runner**

`src/db/mod.rs`:

```rust
pub mod users;
pub mod apps;
pub mod sessions;
pub mod audit;

use std::path::Path;
use rusqlite::Connection;
use anyhow::Result;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// Opens a SQLite connection and runs migrations.
pub fn initialize(db_path: &str) -> Result<Connection> {
    let conn = if db_path == ":memory:" {
        Connection::open_in_memory()?
    } else {
        let path = Path::new(db_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Connection::open(path)?
    };

    // Enable WAL mode for better concurrent read performance
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    embedded::migrations::runner().run(&mut conn)?;

    Ok(conn)
}

#[cfg(test)]
pub fn test_db() -> Connection {
    initialize(":memory:").expect("failed to create test database")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_in_memory() {
        let conn = initialize(":memory:").unwrap();
        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"apps".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
        assert!(tables.contains(&"authorization_codes".to_string()));
        assert!(tables.contains(&"audit_log".to_string()));
        assert!(tables.contains(&"webauthn_credentials".to_string()));
    }
}
```

**Step 3: Run test to verify**

Run: `cargo test --lib db`
Expected: PASS

**Step 4: Add `mod db;` to main.rs**

**Step 5: Commit**

```bash
git add migrations/ src/db/mod.rs src/main.rs
git commit -m "feat: add SQLite database layer with migrations"
```

---

### Task 4: User CRUD database operations

**Files:**
- Create: `src/db/users.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[test]
    fn test_create_and_get_user() {
        let conn = test_db();
        let user = CreateUser {
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            display_name: "Alice".to_string(),
            password_hash: "hash123".to_string(),
            is_admin: false,
        };
        let created = create_user(&conn, &user).unwrap();
        assert_eq!(created.username, "alice");
        assert_eq!(created.email, "alice@example.com");

        let fetched = get_user_by_id(&conn, &created.id).unwrap().unwrap();
        assert_eq!(fetched.username, "alice");
    }

    #[test]
    fn test_get_user_by_username() {
        let conn = test_db();
        let user = CreateUser {
            username: "bob".to_string(),
            email: "bob@example.com".to_string(),
            display_name: "Bob".to_string(),
            password_hash: "hash456".to_string(),
            is_admin: true,
        };
        create_user(&conn, &user).unwrap();

        let fetched = get_user_by_username(&conn, "bob").unwrap().unwrap();
        assert_eq!(fetched.email, "bob@example.com");
        assert!(fetched.is_admin);
    }

    #[test]
    fn test_list_users() {
        let conn = test_db();
        create_user(&conn, &CreateUser {
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
            display_name: "User 1".to_string(),
            password_hash: "h1".to_string(),
            is_admin: false,
        }).unwrap();
        create_user(&conn, &CreateUser {
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
            display_name: "User 2".to_string(),
            password_hash: "h2".to_string(),
            is_admin: false,
        }).unwrap();

        let users = list_users(&conn).unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_duplicate_username_fails() {
        let conn = test_db();
        let user = CreateUser {
            username: "dupe".to_string(),
            email: "dupe1@example.com".to_string(),
            display_name: "Dupe".to_string(),
            password_hash: "h".to_string(),
            is_admin: false,
        };
        create_user(&conn, &user).unwrap();

        let user2 = CreateUser {
            username: "dupe".to_string(),
            email: "dupe2@example.com".to_string(),
            display_name: "Dupe 2".to_string(),
            password_hash: "h".to_string(),
            is_admin: false,
        };
        assert!(create_user(&conn, &user2).is_err());
    }

    #[test]
    fn test_update_user() {
        let conn = test_db();
        let user = CreateUser {
            username: "updatable".to_string(),
            email: "up@example.com".to_string(),
            display_name: "Old Name".to_string(),
            password_hash: "h".to_string(),
            is_admin: false,
        };
        let created = create_user(&conn, &user).unwrap();

        let updates = UpdateUser {
            display_name: Some("New Name".to_string()),
            email: None,
            password_hash: None,
            totp_secret: None,
            is_admin: None,
        };
        update_user(&conn, &created.id, &updates).unwrap();

        let fetched = get_user_by_id(&conn, &created.id).unwrap().unwrap();
        assert_eq!(fetched.display_name, "New Name");
    }

    #[test]
    fn test_delete_user() {
        let conn = test_db();
        let user = CreateUser {
            username: "deleteme".to_string(),
            email: "del@example.com".to_string(),
            display_name: "Del".to_string(),
            password_hash: "h".to_string(),
            is_admin: false,
        };
        let created = create_user(&conn, &user).unwrap();
        delete_user(&conn, &created.id).unwrap();

        let fetched = get_user_by_id(&conn, &created.id).unwrap();
        assert!(fetched.is_none());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib db::users`
Expected: FAIL

**Step 3: Write implementation**

```rust
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub totp_secret: Option<Vec<u8>>,
    pub is_admin: bool,
    pub created_at: String,
    pub updated_at: String,
}

pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub is_admin: bool,
}

pub struct UpdateUser {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub totp_secret: Option<Option<Vec<u8>>>,
    pub is_admin: Option<bool>,
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        email: row.get("email")?,
        display_name: row.get("display_name")?,
        password_hash: row.get("password_hash")?,
        totp_secret: row.get("totp_secret")?,
        is_admin: row.get::<_, bool>("is_admin")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

pub fn create_user(conn: &Connection, user: &CreateUser) -> Result<User> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO users (id, username, email, display_name, password_hash, is_admin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, user.username, user.email, user.display_name, user.password_hash, user.is_admin],
    )?;
    get_user_by_id(conn, &id)?.ok_or_else(|| anyhow::anyhow!("user not found after insert"))
}

pub fn get_user_by_id(conn: &Connection, id: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare("SELECT * FROM users WHERE id = ?1")?;
    let mut rows = stmt.query_map(params![id], row_to_user)?;
    Ok(rows.next().transpose()?)
}

pub fn get_user_by_username(conn: &Connection, username: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare("SELECT * FROM users WHERE username = ?1")?;
    let mut rows = stmt.query_map(params![username], row_to_user)?;
    Ok(rows.next().transpose()?)
}

pub fn list_users(conn: &Connection) -> Result<Vec<User>> {
    let mut stmt = conn.prepare("SELECT * FROM users ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], row_to_user)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn update_user(conn: &Connection, id: &str, updates: &UpdateUser) -> Result<()> {
    let mut sets = Vec::new();
    let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref name) = updates.display_name {
        sets.push("display_name = ?");
        values.push(Box::new(name.clone()));
    }
    if let Some(ref email) = updates.email {
        sets.push("email = ?");
        values.push(Box::new(email.clone()));
    }
    if let Some(ref hash) = updates.password_hash {
        sets.push("password_hash = ?");
        values.push(Box::new(hash.clone()));
    }
    if let Some(ref totp) = updates.totp_secret {
        sets.push("totp_secret = ?");
        values.push(Box::new(totp.clone()));
    }
    if let Some(admin) = updates.is_admin {
        sets.push("is_admin = ?");
        values.push(Box::new(admin));
    }

    if sets.is_empty() {
        return Ok(());
    }

    sets.push("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')");
    let sql = format!("UPDATE users SET {} WHERE id = ?", sets.join(", "));
    values.push(Box::new(id.to_string()));

    let params: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| v.as_ref()).collect();
    conn.execute(&sql, params.as_slice())?;
    Ok(())
}

pub fn delete_user(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
    Ok(())
}
```

**Step 4: Run tests**

Run: `cargo test --lib db::users`
Expected: PASS

**Step 5: Commit**

```bash
git add src/db/users.rs
git commit -m "feat: add user CRUD database operations"
```

---

### Task 5: App (relying party) CRUD database operations

**Files:**
- Create: `src/db/apps.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[test]
    fn test_create_oidc_app() {
        let conn = test_db();
        let app = CreateApp::Oidc {
            name: "My App".to_string(),
            redirect_uris: vec!["https://app.test/callback".to_string()],
        };
        let created = create_app(&conn, &app).unwrap();
        assert_eq!(created.name, "My App");
        assert_eq!(created.protocol, "oidc");
        assert!(!created.client_id.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_create_saml_app() {
        let conn = test_db();
        let app = CreateApp::Saml {
            name: "GitHub".to_string(),
            entity_id: "https://github.com/saml".to_string(),
            acs_url: "https://github.com/saml/acs".to_string(),
        };
        let created = create_app(&conn, &app).unwrap();
        assert_eq!(created.protocol, "saml");
        assert_eq!(created.entity_id.as_deref(), Some("https://github.com/saml"));
    }

    #[test]
    fn test_get_app_by_client_id() {
        let conn = test_db();
        let app = CreateApp::Oidc {
            name: "Test".to_string(),
            redirect_uris: vec!["https://test/cb".to_string()],
        };
        let created = create_app(&conn, &app).unwrap();
        let fetched = get_app_by_client_id(&conn, created.client_id.as_ref().unwrap()).unwrap().unwrap();
        assert_eq!(fetched.id, created.id);
    }

    #[test]
    fn test_list_apps() {
        let conn = test_db();
        create_app(&conn, &CreateApp::Oidc {
            name: "App1".to_string(),
            redirect_uris: vec![],
        }).unwrap();
        create_app(&conn, &CreateApp::Saml {
            name: "App2".to_string(),
            entity_id: "eid".to_string(),
            acs_url: "acs".to_string(),
        }).unwrap();

        let apps = list_apps(&conn).unwrap();
        assert_eq!(apps.len(), 2);
    }

    #[test]
    fn test_delete_app() {
        let conn = test_db();
        let app = create_app(&conn, &CreateApp::Oidc {
            name: "Del".to_string(),
            redirect_uris: vec![],
        }).unwrap();
        delete_app(&conn, &app.id).unwrap();
        assert!(get_app_by_id(&conn, &app.id).unwrap().is_none());
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib db::apps`

**Step 3: Write implementation**

```rust
use anyhow::Result;
use rand::Rng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub client_id: Option<String>,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Option<String>,
    pub entity_id: Option<String>,
    pub acs_url: Option<String>,
    pub name_id_format: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub enum CreateApp {
    Oidc {
        name: String,
        redirect_uris: Vec<String>,
    },
    Saml {
        name: String,
        entity_id: String,
        acs_url: String,
    },
}

fn generate_client_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn row_to_app(row: &rusqlite::Row) -> rusqlite::Result<App> {
    Ok(App {
        id: row.get("id")?,
        name: row.get("name")?,
        protocol: row.get("protocol")?,
        client_id: row.get("client_id")?,
        client_secret_hash: row.get("client_secret_hash")?,
        redirect_uris: row.get("redirect_uris")?,
        entity_id: row.get("entity_id")?,
        acs_url: row.get("acs_url")?,
        name_id_format: row.get("name_id_format")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

pub fn create_app(conn: &Connection, app: &CreateApp) -> Result<App> {
    let id = Uuid::new_v4().to_string();
    match app {
        CreateApp::Oidc { name, redirect_uris } => {
            let client_id = generate_client_id();
            let uris_json = serde_json::to_string(redirect_uris)?;
            conn.execute(
                "INSERT INTO apps (id, name, protocol, client_id, redirect_uris)
                 VALUES (?1, ?2, 'oidc', ?3, ?4)",
                params![id, name, client_id, uris_json],
            )?;
        }
        CreateApp::Saml { name, entity_id, acs_url } => {
            conn.execute(
                "INSERT INTO apps (id, name, protocol, entity_id, acs_url)
                 VALUES (?1, ?2, 'saml', ?3, ?4)",
                params![id, name, entity_id, acs_url],
            )?;
        }
    }
    get_app_by_id(conn, &id)?.ok_or_else(|| anyhow::anyhow!("app not found after insert"))
}

pub fn get_app_by_id(conn: &Connection, id: &str) -> Result<Option<App>> {
    let mut stmt = conn.prepare("SELECT * FROM apps WHERE id = ?1")?;
    let mut rows = stmt.query_map(params![id], row_to_app)?;
    Ok(rows.next().transpose()?)
}

pub fn get_app_by_client_id(conn: &Connection, client_id: &str) -> Result<Option<App>> {
    let mut stmt = conn.prepare("SELECT * FROM apps WHERE client_id = ?1")?;
    let mut rows = stmt.query_map(params![client_id], row_to_app)?;
    Ok(rows.next().transpose()?)
}

pub fn get_app_by_entity_id(conn: &Connection, entity_id: &str) -> Result<Option<App>> {
    let mut stmt = conn.prepare("SELECT * FROM apps WHERE entity_id = ?1")?;
    let mut rows = stmt.query_map(params![entity_id], row_to_app)?;
    Ok(rows.next().transpose()?)
}

pub fn list_apps(conn: &Connection) -> Result<Vec<App>> {
    let mut stmt = conn.prepare("SELECT * FROM apps ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], row_to_app)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn delete_app(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM apps WHERE id = ?1", params![id])?;
    Ok(())
}
```

**Step 4: Run tests**

Run: `cargo test --lib db::apps`
Expected: PASS

**Step 5: Commit**

```bash
git add src/db/apps.rs
git commit -m "feat: add app (relying party) CRUD database operations"
```

---

### Task 6: Session and audit log database operations

**Files:**
- Create: `src/db/sessions.rs`
- Create: `src/db/audit.rs`

**Step 1: Write failing tests for sessions**

`src/db/sessions.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{test_db, users::{create_user, CreateUser}};

    fn setup_user(conn: &Connection) -> String {
        let u = create_user(conn, &CreateUser {
            username: "sessuser".into(),
            email: "sess@test.com".into(),
            display_name: "Sess".into(),
            password_hash: "h".into(),
            is_admin: false,
        }).unwrap();
        u.id
    }

    #[test]
    fn test_create_and_lookup_session() {
        let conn = test_db();
        let uid = setup_user(&conn);
        let sess = create_session(&conn, &uid, "tokenhash123", "1.2.3.4", "Mozilla/5.0", 3600).unwrap();
        assert_eq!(sess.user_id, uid);

        let found = get_session_by_token_hash(&conn, "tokenhash123").unwrap().unwrap();
        assert_eq!(found.id, sess.id);
    }

    #[test]
    fn test_expired_session_not_returned() {
        let conn = test_db();
        let uid = setup_user(&conn);
        // Create session that expired 1 second ago
        create_session(&conn, &uid, "expiredhash", "1.2.3.4", "Mozilla", -1).unwrap();
        let found = get_valid_session_by_token_hash(&conn, "expiredhash").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_delete_session() {
        let conn = test_db();
        let uid = setup_user(&conn);
        let sess = create_session(&conn, &uid, "delhash", "1.2.3.4", "Mozilla", 3600).unwrap();
        delete_session(&conn, &sess.id).unwrap();
        assert!(get_session_by_token_hash(&conn, "delhash").unwrap().is_none());
    }

    #[test]
    fn test_list_sessions() {
        let conn = test_db();
        let uid = setup_user(&conn);
        create_session(&conn, &uid, "h1", "1.1.1.1", "A", 3600).unwrap();
        create_session(&conn, &uid, "h2", "2.2.2.2", "B", 3600).unwrap();
        let sessions = list_sessions(&conn).unwrap();
        assert_eq!(sessions.len(), 2);
    }
}
```

**Step 2: Write failing tests for audit log**

`src/db/audit.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[test]
    fn test_append_and_query_audit_log() {
        let conn = test_db();
        append_audit(&conn, &AuditEntry {
            user_id: Some("user1".into()),
            action: "login_success".into(),
            ip_address: "1.2.3.4".into(),
            detail: serde_json::json!({"method": "password"}),
            app_id: None,
        }).unwrap();

        append_audit(&conn, &AuditEntry {
            user_id: None,
            action: "app_created".into(),
            ip_address: "5.6.7.8".into(),
            detail: serde_json::json!({}),
            app_id: Some("app1".into()),
        }).unwrap();

        let logs = query_audit_log(&conn, &AuditQuery::default()).unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[test]
    fn test_audit_query_filter_by_action() {
        let conn = test_db();
        append_audit(&conn, &AuditEntry {
            user_id: None, action: "login_success".into(),
            ip_address: "".into(), detail: serde_json::json!({}), app_id: None,
        }).unwrap();
        append_audit(&conn, &AuditEntry {
            user_id: None, action: "login_failed".into(),
            ip_address: "".into(), detail: serde_json::json!({}), app_id: None,
        }).unwrap();

        let logs = query_audit_log(&conn, &AuditQuery {
            action: Some("login_failed".into()),
            ..Default::default()
        }).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].action, "login_failed");
    }
}
```

**Step 3: Implement sessions.rs**

```rust
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_active_at: String,
}

fn row_to_session(row: &rusqlite::Row) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        token_hash: row.get("token_hash")?,
        ip_address: row.get("ip_address")?,
        user_agent: row.get("user_agent")?,
        created_at: row.get("created_at")?,
        expires_at: row.get("expires_at")?,
        last_active_at: row.get("last_active_at")?,
    })
}

pub fn create_session(
    conn: &Connection, user_id: &str, token_hash: &str,
    ip_address: &str, user_agent: &str, ttl_seconds: i64,
) -> Result<Session> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?6 || ' seconds'))",
        params![id, user_id, token_hash, ip_address, user_agent, ttl_seconds.to_string()],
    )?;
    get_session_by_id(conn, &id)?.ok_or_else(|| anyhow::anyhow!("session not found after insert"))
}

pub fn get_session_by_id(conn: &Connection, id: &str) -> Result<Option<Session>> {
    let mut stmt = conn.prepare("SELECT * FROM sessions WHERE id = ?1")?;
    let mut rows = stmt.query_map(params![id], row_to_session)?;
    Ok(rows.next().transpose()?)
}

pub fn get_session_by_token_hash(conn: &Connection, token_hash: &str) -> Result<Option<Session>> {
    let mut stmt = conn.prepare("SELECT * FROM sessions WHERE token_hash = ?1")?;
    let mut rows = stmt.query_map(params![token_hash], row_to_session)?;
    Ok(rows.next().transpose()?)
}

pub fn get_valid_session_by_token_hash(conn: &Connection, token_hash: &str) -> Result<Option<Session>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM sessions WHERE token_hash = ?1
         AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"
    )?;
    let mut rows = stmt.query_map(params![token_hash], row_to_session)?;
    Ok(rows.next().transpose()?)
}

pub fn touch_session(conn: &Connection, id: &str, new_expires_at_ttl: i64) -> Result<()> {
    conn.execute(
        "UPDATE sessions SET last_active_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
         expires_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?1 || ' seconds')
         WHERE id = ?2",
        params![new_expires_at_ttl.to_string(), id],
    )?;
    Ok(())
}

pub fn delete_session(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn delete_expired_sessions(conn: &Connection) -> Result<u64> {
    let count = conn.execute(
        "DELETE FROM sessions WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        [],
    )?;
    Ok(count as u64)
}

pub fn list_sessions(conn: &Connection) -> Result<Vec<Session>> {
    let mut stmt = conn.prepare("SELECT * FROM sessions ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], row_to_session)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}
```

**Step 4: Implement audit.rs**

```rust
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub timestamp: String,
    pub user_id: Option<String>,
    pub action: String,
    pub ip_address: String,
    pub detail: serde_json::Value,
    pub app_id: Option<String>,
}

pub struct AuditEntry {
    pub user_id: Option<String>,
    pub action: String,
    pub ip_address: String,
    pub detail: serde_json::Value,
    pub app_id: Option<String>,
}

#[derive(Default)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub user_id: Option<String>,
    pub limit: Option<u32>,
}

pub fn append_audit(conn: &Connection, entry: &AuditEntry) -> Result<()> {
    let detail_str = serde_json::to_string(&entry.detail)?;
    conn.execute(
        "INSERT INTO audit_log (user_id, action, ip_address, detail, app_id)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![entry.user_id, entry.action, entry.ip_address, detail_str, entry.app_id],
    )?;
    Ok(())
}

pub fn query_audit_log(conn: &Connection, query: &AuditQuery) -> Result<Vec<AuditRecord>> {
    let mut sql = "SELECT * FROM audit_log WHERE 1=1".to_string();
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref action) = query.action {
        sql.push_str(" AND action = ?");
        param_values.push(Box::new(action.clone()));
    }
    if let Some(ref uid) = query.user_id {
        sql.push_str(" AND user_id = ?");
        param_values.push(Box::new(uid.clone()));
    }

    sql.push_str(" ORDER BY timestamp DESC");

    let limit = query.limit.unwrap_or(100);
    sql.push_str(&format!(" LIMIT {limit}"));

    let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|v| v.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        let detail_str: String = row.get("detail")?;
        Ok(AuditRecord {
            id: row.get("id")?,
            timestamp: row.get("timestamp")?,
            user_id: row.get("user_id")?,
            action: row.get("action")?,
            ip_address: row.get("ip_address")?,
            detail: serde_json::from_str(&detail_str).unwrap_or(serde_json::json!({})),
            app_id: row.get("app_id")?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}
```

**Step 5: Run all tests**

Run: `cargo test --lib db`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add src/db/sessions.rs src/db/audit.rs
git commit -m "feat: add session and audit log database operations"
```

---

## Phase 3: Crypto Module

### Task 7: Master secret and HKDF key derivation

**Files:**
- Create: `src/crypto/mod.rs`
- Create: `src/crypto/hkdf.rs`
- Modify: `src/main.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "totp-encryption", 32).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_info_different_key() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "key-encryption", 32).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = derive_key(master, "totp-encryption", 32).unwrap();
        let plaintext = b"my-totp-secret-base32";
        let ciphertext = encrypt_aes_gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "key-encryption", 32).unwrap();
        let ciphertext = encrypt_aes_gcm(&k1, b"secret").unwrap();
        assert!(decrypt_aes_gcm(&k2, &ciphertext).is_err());
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib crypto::hkdf`

**Step 3: Implement**

```rust
use anyhow::{Result, anyhow};
use ring::{aead, hkdf, rand as ring_rand, rand::SecureRandom};

/// Derive a key from the master secret using HKDF-SHA256.
pub fn derive_key(master_hex: &str, info: &str, len: usize) -> Result<Vec<u8>> {
    let master_bytes = hex::decode(master_hex)
        .map_err(|e| anyhow!("invalid master secret hex: {e}"))?;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&master_bytes);
    let info_slice = &[info.as_bytes()];
    let okm = prk.expand(info_slice, HkdfLen(len))
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    let mut key = vec![0u8; len];
    okm.fill(&mut key)
        .map_err(|_| anyhow!("HKDF fill failed"))?;
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext.
pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow!("invalid AES key"))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let rng = ring_rand::SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("failed to generate nonce"))?;

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("encryption failed"))?;

    // Prepend nonce
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// Decrypt nonce || ciphertext with AES-256-GCM.
pub fn decrypt_aes_gcm(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("ciphertext too short"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow!("invalid AES key"))?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| anyhow!("invalid nonce"))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("decryption failed"))?;

    Ok(plaintext.to_vec())
}

// Helper to allow HKDF to output arbitrary lengths
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}
```

**Step 4: Run tests**

Run: `cargo test --lib crypto::hkdf`
Expected: PASS

**Step 5: Create `src/crypto/mod.rs`**

```rust
pub mod hkdf;
pub mod keys;
```

**Step 6: Commit**

```bash
git add src/crypto/
git commit -m "feat: add HKDF key derivation and AES-256-GCM encrypt/decrypt"
```

---

### Task 8: Signing key generation and management

**Files:**
- Create: `src/crypto/keys.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_keypair() {
        let kp = generate_ed25519_keypair().unwrap();
        assert!(!kp.private_key_pkcs8.is_empty());
        assert!(!kp.public_key_bytes.is_empty());
        assert!(!kp.kid.is_empty());
    }

    #[test]
    fn test_sign_and_verify_jwt() {
        let kp = generate_ed25519_keypair().unwrap();
        let claims = serde_json::json!({
            "sub": "user123",
            "iss": "https://id.test.com",
            "exp": 9999999999u64,
        });
        let token = sign_jwt_ed25519(&kp, &claims).unwrap();
        assert!(!token.is_empty());
        // Token should have 3 parts
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_save_and_load_keys() {
        let dir = tempfile::tempdir().unwrap();
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let kp = generate_ed25519_keypair().unwrap();
        let path = dir.path().join("ed25519.key.enc");
        save_encrypted_key(&kp.private_key_pkcs8, path.to_str().unwrap(), master).unwrap();

        let loaded = load_encrypted_key(path.to_str().unwrap(), master).unwrap();
        assert_eq!(loaded, kp.private_key_pkcs8);
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib crypto::keys`

**Step 3: Implement**

```rust
use anyhow::{Result, anyhow};
use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
use uuid::Uuid;

use super::hkdf::{encrypt_aes_gcm, decrypt_aes_gcm, derive_key};

pub struct Ed25519Keypair {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
    pub kid: String,
}

pub fn generate_ed25519_keypair() -> Result<Ed25519Keypair> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow!("failed to generate Ed25519 keypair"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow!("failed to parse generated keypair"))?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    let kid = Uuid::new_v4().to_string();

    Ok(Ed25519Keypair {
        private_key_pkcs8: pkcs8.as_ref().to_vec(),
        public_key_bytes: public_key,
        kid,
    })
}

pub fn sign_jwt_ed25519(keypair: &Ed25519Keypair, claims: &serde_json::Value) -> Result<String> {
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(&keypair.private_key_pkcs8);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(keypair.kid.clone());

    let token = jsonwebtoken::encode(&header, claims, &encoding_key)?;
    Ok(token)
}

pub fn save_encrypted_key(key_bytes: &[u8], path: &str, master_hex: &str) -> Result<()> {
    let encryption_key = derive_key(master_hex, "key-encryption", 32)?;
    let encrypted = encrypt_aes_gcm(&encryption_key, key_bytes)?;
    std::fs::write(path, encrypted)?;
    Ok(())
}

pub fn load_encrypted_key(path: &str, master_hex: &str) -> Result<Vec<u8>> {
    let encrypted = std::fs::read(path)?;
    let encryption_key = derive_key(master_hex, "key-encryption", 32)?;
    decrypt_aes_gcm(&encryption_key, &encrypted)
}
```

**Step 4: Run tests**

Run: `cargo test --lib crypto::keys`
Expected: PASS

**Step 5: Commit**

```bash
git add src/crypto/keys.rs
git commit -m "feat: add Ed25519 key generation, JWT signing, encrypted key storage"
```

---

## Phase 4: Auth Engine

### Task 9: Password hashing with argon2id

**Files:**
- Create: `src/auth/mod.rs`
- Create: `src/auth/password.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("correcthorse").unwrap();
        assert!(verify_password("correcthorse", &hash).unwrap());
        assert!(!verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_hash_is_not_plaintext() {
        let hash = hash_password("mysecret").unwrap();
        assert_ne!(hash, "mysecret");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_validate_password_length() {
        assert!(validate_password_strength("short", 12).is_err());
        assert!(validate_password_strength("longenoughpass", 12).is_ok());
    }

    #[test]
    fn test_timing_safe_dummy_verify() {
        // Verifying against a dummy hash should not panic and should return false
        let result = verify_password_or_dummy("anypassword", None).unwrap();
        assert!(!result);
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib auth::password`

**Step 3: Implement**

```rust
use anyhow::{Result, anyhow};
use argon2::{
    password_hash::{SaltString, rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2, Algorithm, Version, Params,
};

/// Hash a password with argon2id using OWASP recommended parameters.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, Some(32))
        .map_err(|e| anyhow!("argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hash error: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow!("invalid hash format: {e}"))?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Verify a password, or run a dummy verification if no hash exists (timing oracle defense).
pub fn verify_password_or_dummy(password: &str, hash: Option<&str>) -> Result<bool> {
    match hash {
        Some(h) => verify_password(password, h),
        None => {
            // Run argon2 against a dummy hash so timing is indistinguishable
            let dummy = "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bnNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let _ = verify_password(password, dummy);
            Ok(false)
        }
    }
}

/// Validate password meets minimum length requirement.
pub fn validate_password_strength(password: &str, min_length: usize) -> Result<()> {
    if password.len() < min_length {
        return Err(anyhow!("password must be at least {min_length} characters"));
    }
    Ok(())
}
```

**Step 4: Run tests**

Run: `cargo test --lib auth::password`
Expected: PASS

**Step 5: Create `src/auth/mod.rs`**

```rust
pub mod password;
pub mod totp;
pub mod webauthn;
pub mod session;
```

**Step 6: Commit**

```bash
git add src/auth/
git commit -m "feat: add argon2id password hashing with timing oracle defense"
```

---

### Task 10: TOTP enrollment and verification

**Files:**
- Create: `src/auth/totp.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        assert!(!secret.base32_secret.is_empty());
        assert!(secret.otpauth_uri.starts_with("otpauth://totp/"));
    }

    #[test]
    fn test_verify_totp_code() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1, 6, 1, 30,
            totp_rs::Secret::Encoded(secret.base32_secret.clone()).to_bytes().unwrap(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp_code(&secret.base32_secret, &code).unwrap());
    }

    #[test]
    fn test_reject_wrong_totp_code() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        assert!(!verify_totp_code(&secret.base32_secret, "000000").unwrap());
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib auth::totp`

**Step 3: Implement**

```rust
use anyhow::{Result, anyhow};
use totp_rs::{Algorithm, TOTP, Secret};

pub struct TotpSecret {
    pub base32_secret: String,
    pub otpauth_uri: String,
}

pub fn generate_totp_secret(username: &str, issuer: &str) -> Result<TotpSecret> {
    let secret = Secret::generate_secret();
    let base32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30,
        secret.to_bytes()
            .map_err(|e| anyhow!("secret decode error: {e}"))?,
    ).map_err(|e| anyhow!("TOTP creation error: {e}"))?;

    let uri = totp.get_url(username, issuer);

    Ok(TotpSecret {
        base32_secret: base32,
        otpauth_uri: uri,
    })
}

pub fn verify_totp_code(base32_secret: &str, code: &str) -> Result<bool> {
    let secret_bytes = Secret::Encoded(base32_secret.to_string())
        .to_bytes()
        .map_err(|e| anyhow!("secret decode error: {e}"))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| anyhow!("TOTP creation error: {e}"))?;

    Ok(totp.check_current(code).unwrap_or(false))
}
```

**Step 4: Run tests**

Run: `cargo test --lib auth::totp`
Expected: PASS

**Step 5: Commit**

```bash
git add src/auth/totp.rs
git commit -m "feat: add TOTP secret generation and verification"
```

---

### Task 11: Session token creation and cookie handling

**Files:**
- Create: `src/auth/session.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64); // 32 bytes as hex
    }

    #[test]
    fn test_hash_token() {
        let token = "abc123";
        let h1 = hash_token(token);
        let h2 = hash_token(token);
        assert_eq!(h1, h2);
        assert_ne!(h1, token);
    }

    #[test]
    fn test_different_tokens_different_hashes() {
        let h1 = hash_token("token1");
        let h2 = hash_token("token2");
        assert_ne!(h1, h2);
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib auth::session`

**Step 3: Implement**

```rust
use ring::{digest, rand::{SecureRandom, SystemRandom}};

/// Generate a cryptographically random session token (32 bytes, hex-encoded).
pub fn generate_session_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("failed to generate random bytes");
    hex::encode(bytes)
}

/// SHA-256 hash a session token for storage.
pub fn hash_token(token: &str) -> String {
    let digest = digest::digest(&digest::SHA256, token.as_bytes());
    hex::encode(digest.as_ref())
}
```

**Step 4: Run tests**

Run: `cargo test --lib auth::session`
Expected: PASS

**Step 5: Commit**

```bash
git add src/auth/session.rs
git commit -m "feat: add session token generation and hashing"
```

---

### Task 12: CSRF token generation and validation

**Files:**
- Create: `src/middleware/mod.rs`
- Create: `src/middleware/csrf.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate_csrf() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let session_id = "sess-123";
        let token = generate_csrf_token(key, session_id).unwrap();
        assert!(validate_csrf_token(key, session_id, &token, 3600).unwrap());
    }

    #[test]
    fn test_csrf_wrong_session_fails() {
        let key = b"0123456789abcdef0123456789abcdef";
        let token = generate_csrf_token(key, "sess-123").unwrap();
        assert!(!validate_csrf_token(key, "sess-456", &token, 3600).unwrap());
    }

    #[test]
    fn test_csrf_expired_fails() {
        let key = b"0123456789abcdef0123456789abcdef";
        let token = generate_csrf_token(key, "sess-123").unwrap();
        // max_age of 0 seconds means it's already expired
        assert!(!validate_csrf_token(key, "sess-123", &token, 0).unwrap());
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib middleware::csrf`

**Step 3: Implement**

```rust
use anyhow::{Result, anyhow};
use ring::hmac;

/// Generate a CSRF token: base64(timestamp || HMAC(session_id || timestamp)).
pub fn generate_csrf_token(key: &[u8], session_id: &str) -> Result<String> {
    let timestamp = chrono::Utc::now().timestamp();
    let ts_bytes = timestamp.to_be_bytes();

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut msg = session_id.as_bytes().to_vec();
    msg.extend_from_slice(&ts_bytes);

    let tag = hmac::sign(&signing_key, &msg);

    let mut token_bytes = ts_bytes.to_vec();
    token_bytes.extend_from_slice(tag.as_ref());

    Ok(base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &token_bytes))
}

/// Validate a CSRF token. Returns true if valid and not expired.
pub fn validate_csrf_token(key: &[u8], session_id: &str, token: &str, max_age_seconds: i64) -> Result<bool> {
    let token_bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)
        .map_err(|_| anyhow!("invalid CSRF token encoding"))?;

    if token_bytes.len() < 8 + 32 {
        return Ok(false);
    }

    let (ts_bytes, mac_bytes) = token_bytes.split_at(8);
    let timestamp = i64::from_be_bytes(ts_bytes.try_into().unwrap());
    let now = chrono::Utc::now().timestamp();

    if now - timestamp > max_age_seconds {
        return Ok(false);
    }

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut msg = session_id.as_bytes().to_vec();
    msg.extend_from_slice(ts_bytes);

    Ok(hmac::verify(&signing_key, &msg, mac_bytes).is_ok())
}
```

**Step 4: Run tests**

Run: `cargo test --lib middleware::csrf`
Expected: PASS

**Step 5: Create `src/middleware/mod.rs`**

```rust
pub mod csrf;
pub mod rate_limit;
pub mod auth;
```

**Step 6: Commit**

```bash
git add src/middleware/
git commit -m "feat: add CSRF token generation and validation"
```

---

### Task 13: Rate limiter (token bucket)

**Files:**
- Create: `src/middleware/rate_limit.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(limiter.check("user1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1"));
    }

    #[test]
    fn test_rate_limiter_independent_keys() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("user1"));
        assert!(limiter.check("user2")); // Different key, should pass
        assert!(!limiter.check("user1")); // Same key, should fail
    }
}
```

**Step 2: Run tests — expect FAIL**

Run: `cargo test --lib middleware::rate_limit`

**Step 3: Implement**

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    max_attempts: u32,
    window_seconds: u64,
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            max_attempts,
            window_seconds,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request is allowed, false if rate limited.
    pub fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_seconds);

        let attempts = buckets.entry(key.to_string()).or_default();

        // Remove expired entries
        attempts.retain(|t| now.duration_since(*t) < window);

        if attempts.len() >= self.max_attempts as usize {
            false
        } else {
            attempts.push(now);
            true
        }
    }

    /// Clean up old entries to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_seconds);
        buckets.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < window);
            !attempts.is_empty()
        });
    }
}
```

**Step 4: Run tests**

Run: `cargo test --lib middleware::rate_limit`
Expected: PASS

**Step 5: Commit**

```bash
git add src/middleware/rate_limit.rs
git commit -m "feat: add in-memory token bucket rate limiter"
```

---

## Phase 5: Axum Server & Login Flow

### Task 14: Axum server setup with app state

**Files:**
- Create: `src/server.rs`
- Modify: `src/main.rs`

**Step 1: Write implementation** (no TDD for server wiring — this is infrastructure)

`src/server.rs`:

```rust
use std::sync::Arc;
use axum::Router;
use rusqlite::Connection;
use std::sync::Mutex;

use crate::config::AppConfig;
use crate::crypto::keys::Ed25519Keypair;
use crate::middleware::rate_limit::RateLimiter;

pub struct AppState {
    pub config: AppConfig,
    pub db: Mutex<Connection>,
    pub ed25519_keypair: Ed25519Keypair,
    pub login_rate_limiter: RateLimiter,
    pub csrf_key: Vec<u8>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Protocol endpoints will be added in later tasks
        // .merge(crate::oidc::routes(state.clone()))
        // .merge(crate::saml::routes(state.clone()))
        // .merge(crate::web::routes(state.clone()))
        // .merge(crate::admin::routes(state.clone()))
        .with_state(state)
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "minikta=info,tower_http=info".into())
        )
        .init();

    tracing::info!("Initializing database at {}", config.database.path);
    let conn = crate::db::initialize(&config.database.path)?;

    // Load or generate signing keys
    let keys_dir = "keys";
    std::fs::create_dir_all(keys_dir)?;
    let ed25519_key_path = format!("{keys_dir}/ed25519.key.enc");

    let ed25519_keypair = if std::path::Path::new(&ed25519_key_path).exists() {
        tracing::info!("Loading existing Ed25519 signing key");
        let private_key = crate::crypto::keys::load_encrypted_key(&ed25519_key_path, &config.secrets.master_secret)?;
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| anyhow::anyhow!("failed to load Ed25519 keypair"))?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        // Load kid from a sidecar file
        let kid = std::fs::read_to_string(format!("{keys_dir}/ed25519.kid"))
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
        Ed25519Keypair { private_key_pkcs8: private_key, public_key_bytes: public_key, kid }
    } else {
        tracing::info!("Generating new Ed25519 signing key");
        let kp = crate::crypto::keys::generate_ed25519_keypair()?;
        crate::crypto::keys::save_encrypted_key(&kp.private_key_pkcs8, &ed25519_key_path, &config.secrets.master_secret)?;
        std::fs::write(format!("{keys_dir}/ed25519.kid"), &kp.kid)?;
        kp
    };

    let csrf_key = crate::crypto::hkdf::derive_key(&config.secrets.master_secret, "csrf-tokens", 32)?;

    let login_rate_limiter = RateLimiter::new(
        config.rate_limit.login_max_attempts,
        config.rate_limit.login_window_seconds,
    );

    let state = Arc::new(AppState {
        config: config.clone(),
        db: Mutex::new(conn),
        ed25519_keypair,
        login_rate_limiter,
        csrf_key,
    });

    let app = build_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("minikta listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Step 2: Update main.rs to call `server::run`**

```rust
Commands::Serve { config: config_path } => {
    let cfg = crate::config::AppConfig::load(&config_path)?;
    crate::server::run(cfg).await?;
}
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles

**Step 4: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: add axum server setup with app state"
```

---

### Task 15: Login page and password authentication endpoint

**Files:**
- Create: `src/web/mod.rs`
- Create: `src/web/login.rs`
- Create: `tests/integration/login_flow.rs`

This is a larger task. The login page will be server-rendered HTML (not part of the Svelte admin SPA — the login page needs to work without JS for accessibility and because SAML/OIDC redirects land here).

**Step 1: Write integration test**

`tests/integration/login_flow.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

// Helper to set up a test app
async fn test_app() -> axum::Router {
    // Setup in-memory test config and state
    // (This will be fleshed out as we build more)
    todo!()
}

#[tokio::test]
async fn test_login_page_returns_html() {
    let app = test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response.into_body().collect().await.unwrap().to_bytes().to_vec()
    ).unwrap();
    assert!(body.contains("<form"));
    assert!(body.contains("username"));
    assert!(body.contains("password"));
}
```

**Step 2: Implement login routes**

`src/web/mod.rs`:

```rust
pub mod login;

use std::sync::Arc;
use axum::Router;
use crate::server::AppState;

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(login::routes())
}
```

`src/web/login.rs` — implement `GET /login` (HTML form) and `POST /login/password` (credential verification, session creation, redirect):

```rust
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

async fn login_page(State(state): State<Arc<AppState>>) -> Html<String> {
    // Generate CSRF token (requires a temporary session concept or stateless token)
    let html = render_login_page(None, None);
    Html(html)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf_token: Option<String>,
    // Preserved from the original OIDC/SAML redirect
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
        // Audit log: failed login
        let _ = crate::db::audit::append_audit(&db, &crate::db::audit::AuditEntry {
            user_id: user.as_ref().map(|u| u.id.clone()),
            action: "login_failed".into(),
            ip_address: String::new(), // TODO: extract from request
            detail: serde_json::json!({"username": form.username}),
            app_id: None,
        });

        return Html(render_login_page(
            Some("Invalid credentials."),
            form.redirect_to.as_deref(),
        )).into_response();
    }

    let user = user.unwrap(); // Safe — if valid is true, user must exist

    // Check if TOTP is enrolled — if so, redirect to TOTP step
    if user.totp_secret.is_some() {
        // TODO: store pending auth state and redirect to /login/totp
        todo!("TOTP step");
    }

    // Create session
    let token = session::generate_session_token();
    let token_hash = session::hash_token(&token);
    let _ = sessions::create_session(
        &db, &user.id, &token_hash, "", "", // TODO: IP + UA
        state.config.session.ttl_seconds as i64,
    );

    // Audit log: successful login
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

async fn logout(State(state): State<Arc<AppState>>) -> Redirect {
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
```

**Step 3: Wire into server router**

In `src/server.rs`, uncomment and add:

```rust
let app = Router::new()
    .merge(crate::web::routes(state.clone()))
    .with_state(state);
```

**Step 4: Verify compilation**

Run: `cargo check`
Expected: Compiles

**Step 5: Commit**

```bash
git add src/web/ src/server.rs
git commit -m "feat: add login page and password authentication endpoint"
```

---

## Phase 6: OIDC Provider

### Task 16: OIDC discovery endpoint

**Files:**
- Create: `src/oidc/mod.rs`
- Create: `src/oidc/discovery.rs`

**Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document() {
        let doc = build_discovery_document("https://id.example.com");
        assert_eq!(doc["issuer"], "https://id.example.com");
        assert_eq!(doc["authorization_endpoint"], "https://id.example.com/oauth/authorize");
        assert_eq!(doc["token_endpoint"], "https://id.example.com/oauth/token");
        assert_eq!(doc["jwks_uri"], "https://id.example.com/.well-known/jwks.json");
    }
}
```

**Step 2: Run tests — expect FAIL**

**Step 3: Implement**

```rust
use axum::{extract::State, response::Json, routing::get, Router};
use std::sync::Arc;
use crate::server::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
}

pub fn build_discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "email", "name", "iss", "aud", "exp", "iat"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    })
}

async fn discovery(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(build_discovery_document(&state.config.server.external_url))
}

async fn jwks(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let pub_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &state.ed25519_keypair.public_key_bytes,
    );

    Json(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": state.ed25519_keypair.kid,
            "x": pub_key_b64,
        }]
    }))
}
```

**Step 4: Run tests**

Run: `cargo test --lib oidc::discovery`
Expected: PASS

**Step 5: Commit**

```bash
git add src/oidc/
git commit -m "feat: add OIDC discovery and JWKS endpoints"
```

---

### Task 17: OIDC authorize endpoint

**Files:**
- Create: `src/oidc/authorize.rs`

Implements `GET /oauth/authorize` — validates client_id, redirect_uri, PKCE; redirects to login if no session; issues authorization code if session exists.

**Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_authorize_request() {
        // Valid request
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: Some("xyz".into()),
            code_challenge: Some("challenge123".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert!(validate_authorize_params(&req).is_ok());
    }

    #[test]
    fn test_reject_missing_code_challenge() {
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        assert!(validate_authorize_params(&req).is_err());
    }

    #[test]
    fn test_reject_non_code_response_type() {
        let req = AuthorizeRequest {
            client_id: "abc123".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "token".into(),
            scope: None,
            state: None,
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert!(validate_authorize_params(&req).is_err());
    }
}
```

**Step 2: Implement**

The authorize handler: validate params → check app exists + redirect_uri matches → check session → redirect to login (preserving query) OR generate auth code and redirect to app.

(Full implementation provided in code — approximately 100 lines covering param validation, auth code generation with SHA-256 hashing, and redirect logic.)

**Step 3: Run tests, commit**

```bash
git commit -m "feat: add OIDC authorize endpoint with PKCE"
```

---

### Task 18: OIDC token endpoint

**Files:**
- Create: `src/oidc/token.rs`

Implements `POST /oauth/token` — exchanges authorization code for id_token + access_token. Validates PKCE code_verifier, client credentials. Mints JWT.

**Step 1–5: TDD cycle** (test code exchange, test PKCE verification failure, test expired code rejection, implement, commit)

```bash
git commit -m "feat: add OIDC token endpoint with JWT minting"
```

---

### Task 19: OIDC userinfo endpoint

**Files:**
- Create: `src/oidc/userinfo.rs`

Implements `GET /oauth/userinfo` — accepts Bearer token, returns user claims.

```bash
git commit -m "feat: add OIDC userinfo endpoint"
```

---

## Phase 7: SAML IdP

### Task 20: SAML metadata endpoint

**Files:**
- Create: `src/saml/mod.rs`
- Create: `src/saml/metadata.rs`

Serves IdP metadata XML at `/saml/metadata` — includes entity ID, SSO endpoint URLs, signing certificate.

```bash
git commit -m "feat: add SAML IdP metadata endpoint"
```

---

### Task 21: SAML SSO endpoint

**Files:**
- Create: `src/saml/sso.rs`

Implements `GET|POST /saml/sso` — parses AuthnRequest, authenticates user (redirect to login if needed), builds signed SAML Response with Assertion, auto-POSTs to SP's ACS URL.

This is the most complex single task. Key subtasks:
1. Parse AuthnRequest (HTTP-Redirect or HTTP-POST binding)
2. Look up SP by entity_id
3. Build SAML Response XML with Assertion, NameID, attributes
4. Sign with RSA-SHA256 using samael
5. Render auto-submit HTML form that POSTs to ACS URL

```bash
git commit -m "feat: add SAML SSO endpoint with signed assertions"
```

---

## Phase 8: Admin REST API

### Task 22: Admin API — user management

**Files:**
- Create: `src/admin/mod.rs`
- Create: `src/admin/users.rs`

CRUD endpoints at `/api/admin/users`. Protected by session middleware + `is_admin` check.

```bash
git commit -m "feat: add admin user management API"
```

---

### Task 23: Admin API — app management

**Files:**
- Create: `src/admin/apps.rs`

CRUD + `/rotate-secret` at `/api/admin/apps`.

```bash
git commit -m "feat: add admin app management API"
```

---

### Task 24: Admin API — sessions and audit log

**Files:**
- Create: `src/admin/sessions.rs`
- Create: `src/admin/audit.rs`

Session list/revoke + audit log query endpoints.

```bash
git commit -m "feat: add admin session and audit log API"
```

---

### Task 25: Auth middleware for admin routes

**Files:**
- Create: `src/middleware/auth.rs`

Axum middleware/extractor that validates session cookie and extracts the current user. Separate `RequireAdmin` extractor that also checks `is_admin`.

```bash
git commit -m "feat: add session auth and admin middleware extractors"
```

---

## Phase 9: Admin Dashboard (Svelte SPA)

### Task 26: Initialize Svelte project

**Files:**
- Create: `admin-ui/package.json`
- Create: `admin-ui/src/App.svelte`
- Create: `admin-ui/src/main.ts`
- Create: `admin-ui/src/lib/api.ts`

Scaffold Svelte SPA with Vite. Create API client that wraps `fetch` calls to `/api/admin/*`.

```bash
git commit -m "feat: scaffold admin UI Svelte project"
```

---

### Task 27: Dashboard page

**Files:**
- Create: `admin-ui/src/pages/Dashboard.svelte`

Shows: active session count, registered app count, recent audit events.

```bash
git commit -m "feat: add admin dashboard page"
```

---

### Task 28: Users management page

**Files:**
- Create: `admin-ui/src/pages/Users.svelte`

Table of users, create/edit modal, TOTP enroll/remove, passkey management.

```bash
git commit -m "feat: add admin users management page"
```

---

### Task 29: Apps management page

**Files:**
- Create: `admin-ui/src/pages/Apps.svelte`

Register OIDC or SAML app, show credentials/metadata URL, delete.

```bash
git commit -m "feat: add admin apps management page"
```

---

### Task 30: Sessions and audit log pages

**Files:**
- Create: `admin-ui/src/pages/Sessions.svelte`
- Create: `admin-ui/src/pages/AuditLog.svelte`

```bash
git commit -m "feat: add admin sessions and audit log pages"
```

---

### Task 31: Embed SPA into Rust binary

**Files:**
- Create: `src/admin/spa.rs`

Use `rust-embed` to serve `admin-ui/dist/` at `/admin/*`. Fallback to `index.html` for SPA routing.

```bash
git commit -m "feat: embed admin SPA into Rust binary with rust-embed"
```

---

## Phase 10: WebAuthn / Passkeys

### Task 32: WebAuthn registration flow

**Files:**
- Create: `src/auth/webauthn.rs`
- Create: `src/web/webauthn.rs`

Registration endpoints: `POST /api/admin/users/:id/webauthn/register-start` and `register-finish`. Uses `webauthn-rs` crate.

```bash
git commit -m "feat: add WebAuthn passkey registration flow"
```

---

### Task 33: WebAuthn authentication flow

**Files:**
- Modify: `src/web/login.rs`
- Modify: `src/web/webauthn.rs`

Login endpoints: `POST /login/webauthn/challenge` and `/login/webauthn/verify`. Integrates with the login page JS.

```bash
git commit -m "feat: add WebAuthn passkey authentication flow"
```

---

## Phase 11: CLI & Init Command

### Task 34: Init command — create admin user

**Files:**
- Modify: `src/main.rs`

`minikta init` — runs migrations, prompts for admin password (via `rpassword` crate), creates admin user.

```bash
git commit -m "feat: add minikta init command for admin user creation"
```

---

### Task 35: Generate-keys command

**Files:**
- Modify: `src/main.rs`

`minikta generate-keys` — generates fresh Ed25519 + RSA keypairs, saves encrypted.

```bash
git commit -m "feat: add minikta generate-keys command"
```

---

## Phase 12: Deployment & Polish

### Task 36: Dockerfile

**Files:**
- Create: `Dockerfile`

Multi-stage build: Node stage builds admin UI, Rust stage compiles binary, final stage is `scratch` or `distroless` with just the binary.

```bash
git commit -m "feat: add multi-stage Dockerfile"
```

---

### Task 37: Integration tests

**Files:**
- Create: `tests/integration/oidc_flow.rs`
- Create: `tests/integration/saml_flow.rs`
- Create: `tests/integration/admin_api.rs`

Full end-to-end tests: create user → register OIDC app → run auth code flow → verify JWT. Same for SAML.

```bash
git commit -m "test: add integration tests for OIDC, SAML, and admin API"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1–2 | Project scaffold & config |
| 2 | 3–6 | Database layer (schema, users, apps, sessions, audit) |
| 3 | 7–8 | Crypto (HKDF, AES-GCM, Ed25519 keys) |
| 4 | 9–13 | Auth engine (passwords, TOTP, sessions, CSRF, rate limiting) |
| 5 | 14–15 | Axum server & login flow |
| 6 | 16–19 | OIDC provider (discovery, authorize, token, userinfo) |
| 7 | 20–21 | SAML IdP (metadata, SSO) |
| 8 | 22–25 | Admin REST API |
| 9 | 26–31 | Admin dashboard (Svelte SPA) |
| 10 | 32–33 | WebAuthn / passkeys |
| 11 | 34–35 | CLI commands |
| 12 | 36–37 | Deployment & integration tests |

**Total: 37 tasks across 12 phases.**
