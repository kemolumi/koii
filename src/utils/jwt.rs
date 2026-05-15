use std::{ fs::File, io::Read, path::Path };

use jsonwebtoken::{ DecodingKey, EncodingKey, Header, Validation };
use nanoid::nanoid;
use serde::{ Deserialize, Serialize };

use crate::env::{
    ACCOUNT_TOKEN_IDENTIFIER_LENGTH,
    JWT_PRIVATE,
    JWT_PUBLIC,
    REFRESH_MAX_AGE,
    TOKEN_MAX_AGE,
};

#[derive(Clone, Serialize, Deserialize)]
pub enum KeyKind {
    AUTHENTICATION,
    REFRESH,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyClaims {
    pub identifier: String,
    pub account_id: String,
    pub kind: KeyKind,
    pub exp: u64,
}

pub struct JwtPair {
    pub token: (KeyClaims, String),
    pub refresh: (KeyClaims, String),
    pub created_at: u64,
}

pub struct JwtService {
    private_key: Option<EncodingKey>,
    public_key: DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
}
impl JwtService {
    pub fn new() -> Self {
        JwtService {
            private_key: {
                if let Some(private_keyring) = quick_read(&JWT_PRIVATE) {
                    Some(EncodingKey::from_ec_pem(&private_keyring).unwrap())
                } else {
                    tracing::warn!(
                        "No private key for JWT installed. Any method calls with private key usage will result in a panic."
                    );
                    None
                }
            },
            public_key: {
                DecodingKey::from_ec_pem(
                    &quick_read(&JWT_PUBLIC).expect("Public key for JWT must be included.")
                ).expect("Public key for JWT must be included.")
            },
            algorithm: jsonwebtoken::Algorithm::ES256,
        }
    }

    /// Will panic if the private key is not provided.
    pub fn generate(&self, account_id: &str) -> JwtPair {
        let identifier = nanoid!(*ACCOUNT_TOKEN_IDENTIFIER_LENGTH);
        let created_at = jsonwebtoken::get_current_timestamp();

        let token_claims = KeyClaims {
            identifier: identifier.clone(),
            account_id: account_id.to_owned(),
            kind: KeyKind::AUTHENTICATION,
            exp: created_at + TOKEN_MAX_AGE.as_secs(),
        };

        let token = jsonwebtoken::jws
            ::encode(
                &Header::new(self.algorithm),
                Some(&token_claims),
                self.private_key.as_ref().unwrap()
            )
            .unwrap();

        let refresh_claims = KeyClaims {
            identifier: identifier.clone(),
            account_id: account_id.to_owned(),
            kind: KeyKind::REFRESH,
            exp: created_at + REFRESH_MAX_AGE.as_secs(),
        };

        let refresh = jsonwebtoken::jws
            ::encode(
                &Header::new(self.algorithm),
                Some(&refresh_claims),
                self.private_key.as_ref().unwrap()
            )
            .unwrap();

        JwtPair {
            token: (
                token_claims,
                format!("{}.{}.{}", token.protected, token.payload, token.signature),
            ),
            refresh: (
                refresh_claims,
                format!("{}.{}.{}", refresh.protected, refresh.payload, refresh.signature),
            ),
            created_at,
        }
    }

    /// Any error happens during verification will return `None`.
    pub fn verify(&self, token: &str, expect_kind: KeyKind) -> Option<KeyClaims> {
        let data = jsonwebtoken::decode::<KeyClaims>(
            token,
            &self.public_key,
            &Validation::new(self.algorithm)
        );

        let claims = match data {
            Ok(data) => data.claims,
            Err(_) => {
                return None;
            }
        };

        return match expect_kind {
            KeyKind::AUTHENTICATION =>
                match claims.kind {
                    KeyKind::AUTHENTICATION => Some(claims),
                    KeyKind::REFRESH => None,
                }
            KeyKind::REFRESH =>
                match claims.kind {
                    KeyKind::AUTHENTICATION => None,
                    KeyKind::REFRESH => Some(claims),
                }
        };
    }
}

fn quick_read(name: &str) -> Option<Vec<u8>> {
    let mut keyring = vec![];
    if let Ok(mut reader) = File::open(Path::new(name)) {
        reader.read_to_end(&mut keyring).unwrap();
        return Some(keyring);
    }
    return None;
}
