use std::{ fs::File, io::Read, path::Path };

use jsonwebtoken::{ DecodingKey, EncodingKey, Header, Validation };
use serde::{ Deserialize, Serialize };

use crate::env::{ JWT_PRIVATE, JWT_PUBLIC };

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyKind {
    /// Access token of the user.
    ///
    /// This type of token stays in cookie field for koii's subservice to know which user it is.
    Authentication,

    /// Refresh token of the user.
    ///
    /// This type of token stays in cookie field for /refresh endpoint.
    Refresh,

    /// Temporary token for logged in user, but requires UPGRADE token to turn it into AUTHENTICATION.
    ///
    /// This token is only given to a user with at least one MFA method enabled.
    ///
    /// NEVER PUT THIS TOKEN IN COOKIE.
    PartialLogin,

    /// MFA Upgrade token for user after verified via MFA.
    ///
    /// NEVER PUT THIS TOKEN IN COOKIE.
    MfaUpgrade,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyClaims {
    pub account_id: String,
    pub identifier: String,
    pub kind: KeyKind,
    pub exp: u64,
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
    pub fn generate(
        &self,
        account_id: String,
        identifier: String,
        kind: KeyKind,
        exp: u64
    ) -> (KeyClaims, String) {
        let token_claims = KeyClaims {
            account_id: account_id,
            identifier: identifier,
            kind,
            exp,
        };

        let token = jsonwebtoken::jws
            ::encode(
                &Header::new(self.algorithm),
                Some(&token_claims),
                self.private_key.as_ref().unwrap()
            )
            .unwrap();

        (token_claims, format!("{}.{}.{}", token.protected, token.payload, token.signature))
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

        return match expect_kind == claims.kind {
            true => Some(claims),
            false => None,
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
