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
    let mut conn = if db_path == ":memory:" {
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
