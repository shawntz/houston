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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_db;

    #[test]
    fn test_append_and_query_audit_log() {
        let conn = test_db();
        // Create a real user so FK constraint is satisfied
        use crate::db::users::{create_user, CreateUser};
        let user = create_user(&conn, &CreateUser {
            username: "audituser".into(),
            email: "audit@test.com".into(),
            display_name: "Audit".into(),
            password_hash: "h".into(),
            is_admin: false,
        }).unwrap();

        append_audit(&conn, &AuditEntry {
            user_id: Some(user.id.clone()),
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
            app_id: None,
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
