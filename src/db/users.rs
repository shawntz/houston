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
