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
