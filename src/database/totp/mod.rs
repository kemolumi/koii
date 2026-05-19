use crate::database::totp::{ store::TotpStoreOperations, code::TotpUsedCodeOperations };

pub mod store;
pub mod code;

pub struct TotpOperations {
    pub store: TotpStoreOperations,
    pub code: TotpUsedCodeOperations,
}
