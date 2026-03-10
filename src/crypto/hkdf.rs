use anyhow::{Result, anyhow};
use ring::{aead, hkdf, rand as ring_rand, rand::SecureRandom};

/// Derive a key from the master secret using HKDF-SHA256.
pub fn derive_key(master_hex: &str, info: &str, len: usize) -> Result<Vec<u8>> {
    let master_bytes = hex::decode(master_hex)
        .map_err(|e| anyhow!("invalid master secret hex: {e}"))?;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&master_bytes);
    let info_slice = &[info.as_bytes()];
    let okm = prk.expand(info_slice, HkdfLen(len))
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    let mut key = vec![0u8; len];
    okm.fill(&mut key)
        .map_err(|_| anyhow!("HKDF fill failed"))?;
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext.
pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow!("invalid AES key"))?;
    let sealing_key = aead::LessSafeKey::new(unbound_key);

    let rng = ring_rand::SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("failed to generate nonce"))?;

    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("encryption failed"))?;

    // Prepend nonce
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// Decrypt nonce || ciphertext with AES-256-GCM.
pub fn decrypt_aes_gcm(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("ciphertext too short"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow!("invalid AES key"))?;
    let opening_key = aead::LessSafeKey::new(unbound_key);

    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| anyhow!("invalid nonce"))?;

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("decryption failed"))?;

    Ok(plaintext.to_vec())
}

// Helper to allow HKDF to output arbitrary lengths
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "totp-encryption", 32).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_info_different_key() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "key-encryption", 32).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = derive_key(master, "totp-encryption", 32).unwrap();
        let plaintext = b"my-totp-secret-base32";
        let ciphertext = encrypt_aes_gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let master = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let k1 = derive_key(master, "totp-encryption", 32).unwrap();
        let k2 = derive_key(master, "key-encryption", 32).unwrap();
        let ciphertext = encrypt_aes_gcm(&k1, b"secret").unwrap();
        assert!(decrypt_aes_gcm(&k2, &ciphertext).is_err());
    }
}
