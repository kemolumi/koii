use serde::{ Deserialize, Serialize };
use totp_rs::{ TOTP, TotpUrlError };

use crate::env::TOTP_SECRET_LENGTH;

#[derive(Clone, Serialize, Deserialize)]
pub struct Totp {
    pub totp: TOTP,
}

pub fn create_totp(name: String) -> Result<TOTP, TotpUrlError> {
    TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        nanoid::rngs::default(*TOTP_SECRET_LENGTH),
        Some("Koii".to_string()),
        name.clone()
    )
}
