use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAppAssignment {
    pub user_id: String,
    pub app_id: String,
    pub assigned_at: String,
}

pub fn assign_user_to_app(conn: &Connection, user_id: &str, app_id: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO user_app_assignments (user_id, app_id) VALUES (?1, ?2)",
        params![user_id, app_id],
    )?;
    Ok(())
}

pub fn unassign_user_from_app(conn: &Connection, user_id: &str, app_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM user_app_assignments WHERE user_id = ?1 AND app_id = ?2",
        params![user_id, app_id],
    )?;
    Ok(())
}

pub fn is_user_assigned_to_app(conn: &Connection, user_id: &str, app_id: &str) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM user_app_assignments WHERE user_id = ?1 AND app_id = ?2",
        params![user_id, app_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn get_apps_for_user(conn: &Connection, user_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT app_id FROM user_app_assignments WHERE user_id = ?1"
    )?;
    let rows = stmt.query_map(params![user_id], |row| row.get(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_users_for_app(conn: &Connection, app_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM user_app_assignments WHERE app_id = ?1"
    )?;
    let rows = stmt.query_map(params![app_id], |row| row.get(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{test_db, users, apps};

    fn setup() -> (Connection, String, String) {
        let conn = test_db();
        let user = users::create_user(&conn, &users::CreateUser {
            username: "testuser".into(),
            email: "test@test.com".into(),
            display_name: "Test".into(),
            password_hash: "hash".into(),
            is_admin: false,
        }).unwrap();
        let app = apps::create_app(&conn, &apps::CreateApp::Oidc {
            name: "App".into(),
            redirect_uris: vec![],
        }).unwrap();
        (conn, user.id, app.id)
    }

    #[test]
    fn test_assign_and_check() {
        let (conn, user_id, app_id) = setup();
        assert!(!is_user_assigned_to_app(&conn, &user_id, &app_id).unwrap());
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        assert!(is_user_assigned_to_app(&conn, &user_id, &app_id).unwrap());
    }

    #[test]
    fn test_unassign() {
        let (conn, user_id, app_id) = setup();
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        unassign_user_from_app(&conn, &user_id, &app_id).unwrap();
        assert!(!is_user_assigned_to_app(&conn, &user_id, &app_id).unwrap());
    }

    #[test]
    fn test_get_apps_for_user() {
        let (conn, user_id, app_id) = setup();
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        let apps = get_apps_for_user(&conn, &user_id).unwrap();
        assert_eq!(apps, vec![app_id]);
    }

    #[test]
    fn test_get_users_for_app() {
        let (conn, user_id, app_id) = setup();
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        let users = get_users_for_app(&conn, &app_id).unwrap();
        assert_eq!(users, vec![user_id]);
    }

    #[test]
    fn test_duplicate_assign_is_idempotent() {
        let (conn, user_id, app_id) = setup();
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        assign_user_to_app(&conn, &user_id, &app_id).unwrap();
        let apps = get_apps_for_user(&conn, &user_id).unwrap();
        assert_eq!(apps.len(), 1);
    }
}
