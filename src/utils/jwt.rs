use std::{ fs::File, io::Read, path::Path, time::Duration };

use jsonwebtoken::{ DecodingKey, EncodingKey, Header, Validation };
use serde::{ Deserialize, Serialize };

use crate::env::{ JWT_PRIVATE, JWT_PUBLIC };

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyKind {
    /// Access token of the user.
    ///
    /// The identifier field is shared with `Refresh`.
    ///
    /// This type of token stays in cookie field.
    Authentication,

    /// Refresh token of the user.
    ///
    /// The identifier field is shared with `Authentication`.
    ///
    /// This type of token stays in cookie field for /account/refresh endpoint.
    Refresh,

    /// A temporary token for logged in user when MFA step is required.
    ///
    /// The identifier field is unique to this type of token, **DO NOT** reuse.
    ///
    /// **NEVER PUT THIS TOKEN IN COOKIE.**
    MfaLogin,

    /// A token with full control over a user, requires both `Authentication` and `MfaUpgrade` token to upgrade to.
    ///
    /// The identifier field is unique to this type of token, **DO NOT** reuse.
    ///
    /// **NEVER PUT THIS TOKEN IN COOKIE.**
    Sudo,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyClaims {
    pub account_id: String,
    pub identifier: String,
    pub kind: KeyKind,
    pub iat: Duration,
    pub exp: Duration,
}

#[derive(Clone, Serialize, Deserialize)]
struct RawKeyClaims {
    pub account_id: String,
    pub identifier: String,
    pub kind: KeyKind,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone)]
pub struct JwtToken {
    pub claims: KeyClaims,
    pub signed: String,
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
    pub fn generate(&self, claims: KeyClaims) -> String {
        let raw_claims = RawKeyClaims {
            account_id: claims.account_id,
            identifier: claims.identifier,
            kind: claims.kind,
            iat: claims.iat.as_secs(),
            exp: claims.exp.as_secs(),
        };

        let token = jsonwebtoken::jws
            ::encode(
                &Header::new(self.algorithm),
                Some(&raw_claims),
                self.private_key.as_ref().unwrap()
            )
            .unwrap();

        format!("{}.{}.{}", token.protected, token.payload, token.signature)
    }

    /// Any error happens during verification will return `None`.
    pub fn verify(&self, token: &str, expect_kind: KeyKind) -> Option<KeyClaims> {
        let data = jsonwebtoken::decode::<RawKeyClaims>(
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

        let claims = KeyClaims {
            account_id: claims.account_id,
            identifier: claims.identifier,
            kind: claims.kind,
            iat: Duration::from_secs(claims.iat),
            exp: Duration::from_secs(claims.exp),
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
