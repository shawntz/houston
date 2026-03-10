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
