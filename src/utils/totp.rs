use std::time::SystemTimeError;

use mongodb::bson::Binary;
use serde::{ Deserialize, Serialize };
use totp_rs::{ SecretParseError, TOTP, TotpUrlError };
use thiserror::Error;

use crate::env::TOTP_SECRET_LENGTH;

#[derive(Clone, Serialize, Deserialize)]
pub struct Totp {
    pub secret: Binary,
    pub url: String,
    pub name: String,
}

#[derive(Error, Debug)]
pub enum TotpError {
    #[error("TOTP malformed")] InvalidTotp(#[from] TotpUrlError),
    #[error("Secret malformed")] InvalidSecret(#[from] SecretParseError),
    #[error("Time error")] TimeError(#[from] SystemTimeError),
}

impl Totp {
    pub fn new(name: String) -> Result<Self, TotpError> {
        let secret = nanoid::rngs::default(*TOTP_SECRET_LENGTH);

        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret.clone(),
            Some("Koii".to_string()),
            name.clone()
        )?;

        Ok(Totp {
            secret: Binary {
                subtype: mongodb::bson::spec::BinarySubtype::Generic,
                bytes: secret,
            },
            url: totp.get_url(),
            name,
        })
    }

    pub fn verify(&self, code: &str) -> Result<bool, TotpError> {
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            self.secret.clone().bytes,
            Some("Koii".to_string()),
            self.name.clone()
        )?;

        Ok(totp.check_current(code)?)
    }
}
