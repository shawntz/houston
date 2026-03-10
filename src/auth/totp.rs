use anyhow::{Result, anyhow};
use totp_rs::{Algorithm, TOTP, Secret};

pub struct TotpSecret {
    pub base32_secret: String,
    pub otpauth_uri: String,
}

pub fn generate_totp_secret(username: &str, issuer: &str) -> Result<TotpSecret> {
    let secret = Secret::generate_secret();
    let base32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30,
        secret.to_bytes()
            .map_err(|e| anyhow!("secret decode error: {e}"))?,
        Some(issuer.to_string()),
        username.to_string(),
    ).map_err(|e| anyhow!("TOTP creation error: {e}"))?;

    let uri = totp.get_url();

    Ok(TotpSecret {
        base32_secret: base32,
        otpauth_uri: uri,
    })
}

pub fn verify_totp_code(base32_secret: &str, code: &str) -> Result<bool> {
    let secret_bytes = Secret::Encoded(base32_secret.to_string())
        .to_bytes()
        .map_err(|e| anyhow!("secret decode error: {e}"))?;

    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30, secret_bytes,
        None, "verify".to_string(),
    ).map_err(|e| anyhow!("TOTP creation error: {e}"))?;

    Ok(totp.check_current(code).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        assert!(!secret.base32_secret.is_empty());
        assert!(secret.otpauth_uri.starts_with("otpauth://totp/"));
    }

    #[test]
    fn test_verify_totp_code() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1, 6, 1, 30,
            totp_rs::Secret::Encoded(secret.base32_secret.clone()).to_bytes().unwrap(),
            None, "test".to_string(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp_code(&secret.base32_secret, &code).unwrap());
    }

    #[test]
    fn test_reject_wrong_totp_code() {
        let secret = generate_totp_secret("alice", "minikta").unwrap();
        assert!(!verify_totp_code(&secret.base32_secret, "000000").unwrap());
    }
}
