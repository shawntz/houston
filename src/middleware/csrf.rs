use anyhow::{Result, anyhow};
use base64::Engine;
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

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes))
}

/// Validate a CSRF token. Returns true if valid and not expired.
pub fn validate_csrf_token(key: &[u8], session_id: &str, token: &str, max_age_seconds: i64) -> Result<bool> {
    let token_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)
        .map_err(|_| anyhow!("invalid CSRF token encoding"))?;

    if token_bytes.len() < 8 + 32 {
        return Ok(false);
    }

    let (ts_bytes, mac_bytes) = token_bytes.split_at(8);
    let timestamp = i64::from_be_bytes(ts_bytes.try_into().unwrap());
    let now = chrono::Utc::now().timestamp();

    if now - timestamp >= max_age_seconds {
        return Ok(false);
    }

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut msg = session_id.as_bytes().to_vec();
    msg.extend_from_slice(ts_bytes);

    Ok(hmac::verify(&signing_key, &msg, mac_bytes).is_ok())
}

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
