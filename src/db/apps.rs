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

pub fn generate_new_client_id() -> String {
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
            let client_id = generate_new_client_id();
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
