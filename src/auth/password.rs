use anyhow::{Result, anyhow};
use argon2::{
    password_hash::{SaltString, rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2, Algorithm, Version, Params,
};

/// Hash a password with argon2id using OWASP recommended parameters.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, Some(32))
        .map_err(|e| anyhow!("argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hash error: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow!("invalid hash format: {e}"))?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Verify a password, or run a dummy verification if no hash exists (timing oracle defense).
pub fn verify_password_or_dummy(password: &str, hash: Option<&str>) -> Result<bool> {
    match hash {
        Some(h) => verify_password(password, h),
        None => {
            // Run argon2 against a dummy hash so timing is indistinguishable
            let dummy = "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bnNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let _ = verify_password(password, dummy);
            Ok(false)
        }
    }
}

/// Validate password meets minimum length requirement.
pub fn validate_password_strength(password: &str, min_length: usize) -> Result<()> {
    if password.len() < min_length {
        return Err(anyhow!("password must be at least {min_length} characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("correcthorse").unwrap();
        assert!(verify_password("correcthorse", &hash).unwrap());
        assert!(!verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_hash_is_not_plaintext() {
        let hash = hash_password("mysecret").unwrap();
        assert_ne!(hash, "mysecret");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_validate_password_length() {
        assert!(validate_password_strength("short", 12).is_err());
        assert!(validate_password_strength("longenoughpass", 12).is_ok());
    }

    #[test]
    fn test_timing_safe_dummy_verify() {
        let result = verify_password_or_dummy("anypassword", None).unwrap();
        assert!(!result);
    }
}
