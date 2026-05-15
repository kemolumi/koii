use std::{ net::SocketAddr, sync::LazyLock, time::Duration };
use url::Url;

// Any variables inside of this file can only be used AFTER `dotenv::dotenv().ok()`.
// Failing to comply this will make the whole thing panic.

/// Interface for the server to run on.
pub const HOST: LazyLock<SocketAddr> = LazyLock::new(||
    get_env_value("HOST").parse::<SocketAddr>().unwrap()
);

/// Origin domain is used for CORS and passkey.
pub const ORIGIN_DOMAIN: LazyLock<Url> = LazyLock::new(||
    Url::parse(&get_env_value("ORIGIN_DOMAIN")).unwrap()
);

// File path for SSL when hosting in secure context.
pub const SSL_CERT: LazyLock<String> = LazyLock::new(|| get_env_value("SSL_CERT"));
pub const SSL_KEY: LazyLock<String> = LazyLock::new(|| get_env_value("SSL_KEY"));

// File path for jsonwebtoken to encrypt in ES256.
pub const JWT_PUBLIC: LazyLock<String> = LazyLock::new(|| get_env_value("JWT_PUBLIC"));
pub const JWT_PRIVATE: LazyLock<String> = LazyLock::new(|| get_env_value("JWT_PRIVATE"));

// Databases address.
pub const MONGODB_CONNECTION: LazyLock<String> = LazyLock::new(||
    get_env_value("MONGODB_CONNECTION")
);
pub const REDIS_HOST: LazyLock<String> = LazyLock::new(|| get_env_value("REDIS_HOST"));

// 3rd-party API secrets.
pub const TURNSTILE_SECRET: LazyLock<String> = LazyLock::new(|| get_env_value("TURNSTILE_SECRET"));
pub const RESEND_TOKEN: LazyLock<String> = LazyLock::new(|| get_env_value("RESEND_TOKEN"));

// Time based configs.
pub const TOKEN_MAX_AGE: LazyLock<Duration> = LazyLock::new(|| secs_from_env("TOKEN_MAX_AGE"));
pub const REFRESH_MAX_AGE: LazyLock<Duration> = LazyLock::new(|| secs_from_env("REFRESH_MAX_AGE"));
pub const SUDO_MAX_AGE: LazyLock<Duration> = LazyLock::new(|| secs_from_env("SUDO_MAX_AGE"));
pub const EMAIL_VERIFY_EXPIRE: LazyLock<Duration> = LazyLock::new(||
    secs_from_env("EMAIL_VERIFY_EXPIRE")
);
pub const ACCOUNT_DELETE_WINDOW: LazyLock<Duration> = LazyLock::new(||
    secs_from_env("ACCOUNT_DELETE_WINDOW")
);
pub const TOTP_CODE_VOID_WINDOW: LazyLock<Duration> = LazyLock::new(||
    secs_from_env("TOTP_CODE_VOID_WINDOW")
);

// Argon2id configs.
pub const ARGON2_MEMORY_COST: LazyLock<u32> = LazyLock::new(
    || parse_env_number("ARGON2_MEMORY_COST") as u32
);
pub const ARGON2_PARALLELISM_COST: LazyLock<u32> = LazyLock::new(
    || parse_env_number("ARGON2_PARALLELISM_COST") as u32
);
pub const ARGON2_TIME_COST: LazyLock<u32> = LazyLock::new(
    || parse_env_number("ARGON2_TIME_COST") as u32
);
pub const ARGON2_OUTPUT_LENGTH: LazyLock<usize> = LazyLock::new(||
    parse_env_number("ARGON2_OUTPUT_LENGTH")
);

// Random generation lengths.
pub const ACCOUNT_ID_LENGTH: LazyLock<usize> = LazyLock::new(||
    parse_env_number("ACCOUNT_ID_LENGTH")
);
pub const ACCOUNT_TOKEN_IDENTIFIER_LENGTH: LazyLock<usize> = LazyLock::new(||
    parse_env_number("ACCOUNT_TOKEN_IDENTIFIER_LENGTH")
);
pub const EMAIL_VERIFY_CODE_LENGTH: LazyLock<usize> = LazyLock::new(||
    parse_env_number("EMAIL_VERIFY_CODE_LENGTH")
);
pub const TOTP_SECRET_LENGTH: LazyLock<usize> = LazyLock::new(||
    parse_env_number("TOTP_SECRET_LENGTH")
);

fn get_env_value(key: &str) -> String {
    std::env::var(key).expect(&format!("{key} must be set in .env file."))
}

fn parse_env_number(key: &str) -> usize {
    get_env_value(key).parse::<usize>().unwrap()
}

fn secs_from_env(key: &str) -> Duration {
    Duration::from_secs(get_env_value(key).parse::<u64>().unwrap())
}
