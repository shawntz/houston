use std::collections::HashMap;
use std::sync::Mutex;
use webauthn_rs::prelude::*;

/// In-memory store for WebAuthn registration/authentication state.
/// These are short-lived challenge-response pairs (< 5 min lifetime).
pub struct WebauthnState {
    pub reg_states: Mutex<HashMap<String, PasskeyRegistration>>,
    pub auth_states: Mutex<HashMap<String, PasskeyAuthentication>>,
}

impl WebauthnState {
    pub fn new() -> Self {
        Self {
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        }
    }
}

/// Create a Webauthn instance for the given RP ID and origin.
pub fn build_webauthn(rp_id: &str, rp_origin: &url::Url) -> Webauthn {
    let builder = WebauthnBuilder::new(rp_id, rp_origin)
        .expect("Invalid WebAuthn configuration");
    builder.build().expect("Failed to build Webauthn")
}

/// Store a credential in the database.
/// The entire Passkey is serialized to JSON and stored in the public_key column.
pub fn save_credential(
    conn: &rusqlite::Connection,
    user_id: &str,
    cred: &Passkey,
    name: &str,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let cred_id = serde_json::to_vec(cred.cred_id())?;
    let passkey_json = serde_json::to_vec(cred)?;

    conn.execute(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, name)
         VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        rusqlite::params![id, user_id, cred_id, passkey_json, name],
    )?;
    Ok(())
}

/// Load all passkeys for a user.
pub fn load_credentials(
    conn: &rusqlite::Connection,
    user_id: &str,
) -> anyhow::Result<Vec<Passkey>> {
    let mut stmt = conn.prepare(
        "SELECT public_key FROM webauthn_credentials WHERE user_id = ?1"
    )?;
    let rows = stmt.query_map(rusqlite::params![user_id], |row| {
        let data: Vec<u8> = row.get(0)?;
        Ok(data)
    })?;

    let mut creds = Vec::new();
    for row in rows {
        let data = row?;
        if let Ok(cred) = serde_json::from_slice::<Passkey>(&data) {
            creds.push(cred);
        }
    }
    Ok(creds)
}

/// Save updated passkey back to database after authentication
/// (updates the serialized passkey which includes the counter).
pub fn update_credential(
    conn: &rusqlite::Connection,
    cred: &Passkey,
) -> anyhow::Result<()> {
    let cred_id_json = serde_json::to_vec(cred.cred_id())?;
    let passkey_json = serde_json::to_vec(cred)?;
    conn.execute(
        "UPDATE webauthn_credentials SET public_key = ?1, last_used_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
         WHERE credential_id = ?2",
        rusqlite::params![passkey_json, cred_id_json],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_state_creation() {
        let state = WebauthnState::new();
        assert!(state.reg_states.lock().unwrap().is_empty());
        assert!(state.auth_states.lock().unwrap().is_empty());
    }

    #[test]
    fn test_build_webauthn() {
        let origin = url::Url::parse("https://id.example.com").unwrap();
        let webauthn = build_webauthn("id.example.com", &origin);
        let _ = webauthn;
    }
}
