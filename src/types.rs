use serde::{ Deserialize, Serialize };

macro_rules! type_string {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", &self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.0
            }
        }
        
        impl From<$name> for mongodb::bson::Bson {
            fn from(v: $name) -> Self {
                mongodb::bson::Bson::String(v.0)
            }
        }
    };
}

type_string!(AccountId);
type_string!(Identifier);
type_string!(RawPassword);
type_string!(HashedPassword);
type_string!(EmailAddress);
type_string!(VerifyCode);
type_string!(TotpCode);
type_string!(AName);
type_string!(SignedKey);
type_string!(JwtString);
