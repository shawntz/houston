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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 8080,
                external_url: "https://localhost".into(),
                require_https: false,
            },
            secrets: SecretsConfig {
                master_secret: "test_secret_0000000000000000000000000000000000000000000000000000".into(),
            },
            database: DatabaseConfig::default(),
            session: SessionConfig::default(),
            rate_limit: RateLimitConfig::default(),
            password: PasswordConfig::default(),
        }
    }
}

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
