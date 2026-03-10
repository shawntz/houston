use anyhow::{Result, anyhow};
use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
use uuid::Uuid;

use super::hkdf::{encrypt_aes_gcm, decrypt_aes_gcm, derive_key};

pub struct Ed25519Keypair {
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
    pub kid: String,
}

pub fn generate_ed25519_keypair() -> Result<Ed25519Keypair> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow!("failed to generate Ed25519 keypair"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow!("failed to parse generated keypair"))?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    let kid = Uuid::new_v4().to_string();

    Ok(Ed25519Keypair {
        private_key_pkcs8: pkcs8.as_ref().to_vec(),
        public_key_bytes: public_key,
        kid,
    })
}

pub fn sign_jwt_ed25519(keypair: &Ed25519Keypair, claims: &serde_json::Value) -> Result<String> {
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(&keypair.private_key_pkcs8);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(keypair.kid.clone());

    let token = jsonwebtoken::encode(&header, claims, &encoding_key)?;
    Ok(token)
}

pub fn save_encrypted_key(key_bytes: &[u8], path: &str, master_hex: &str) -> Result<()> {
    let encryption_key = derive_key(master_hex, "key-encryption", 32)?;
    let encrypted = encrypt_aes_gcm(&encryption_key, key_bytes)?;
    std::fs::write(path, encrypted)?;
    Ok(())
}

pub fn load_encrypted_key(path: &str, master_hex: &str) -> Result<Vec<u8>> {
    let encrypted = std::fs::read(path)?;
    let encryption_key = derive_key(master_hex, "key-encryption", 32)?;
    decrypt_aes_gcm(&encryption_key, &encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_keypair() {
        let kp = generate_ed25519_keypair().unwrap();
        assert!(!kp.private_key_pkcs8.is_empty());
        assert!(!kp.public_key_bytes.is_empty());
        assert!(!kp.kid.is_empty());
    }

    #[test]
    fn test_sign_and_verify_jwt() {
        let kp = generate_ed25519_keypair().unwrap();
        let claims = serde_json::json!({
            "sub": "user123",
            "iss": "https://id.test.com",
            "exp": 9999999999u64,
        });
        let token = sign_jwt_ed25519(&kp, &claims).unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_save_and_load_keys() {
        let dir = tempfile::tempdir().unwrap();
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let kp = generate_ed25519_keypair().unwrap();
        let path = dir.path().join("ed25519.key.enc");
        save_encrypted_key(&kp.private_key_pkcs8, path.to_str().unwrap(), master).unwrap();

        let loaded = load_encrypted_key(path.to_str().unwrap(), master).unwrap();
        assert_eq!(loaded, kp.private_key_pkcs8);
    }
}
