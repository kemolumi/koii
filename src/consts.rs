use std::time::Duration;

// Time based variables.
pub const TOKEN_MAX_AGE: Duration = Duration::from_mins(30);
pub const REFRESH_MAX_AGE: Duration = Duration::from_hours(15 * 24);
pub const SUDO_MAX_AGE: Duration = Duration::from_mins(5);
pub const EMAIL_VERIFY_EXPIRE: Duration = Duration::from_mins(10);
pub const ACCOUNT_DELETE_WINDOW: Duration = Duration::from_hours(30 * 24);

// JWT variables.
pub const JWT_VALIDATION_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::ES256;

// Argon2 ariables.
pub const ARGON2_MEMORY_COST: u32 = 128 * 1024; // 128 mb
pub const ARGON2_PARALLELISM_COST: u32 = 1;
pub const ARGON2_TIME_COST: u32 = 5;
pub const ARGON2_OUTPUT_LENGTH: usize = 64; // 64 bytes

// Generation length variables
pub const ACCOUNT_ID_LENGTH: usize = 64;
pub const ACCOUNT_TOKEN_IDENTIFIER_LENGTH: usize = 32;
pub const EMAIL_VERIFY_CODE_LENGTH: usize = 64;

// TOTP defaults
pub const TOTP_SECRET_LENGTH: usize = 128;
pub const TOTP_CODE_VOID_WINDOW: Duration = Duration::from_secs(90);

// Passkey defaults
pub const PASSKEY_ID: &str = "neurs.koii";
pub const PASSKEY_ORIGIN_DOMAIN: &str = "https://auth.koii.space";
