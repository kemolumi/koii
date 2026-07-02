use crate::{
    database::{
        account::AccountOperations,
        auth::AuthOperations,
        mfa_login::MfaLoginOperations,
        sudo::SudoOperations,
        totp::{ TotpOperations, code::TotpUsedCodeOperations, store::TotpStoreOperations },
    },
    env::{ MONGODB_CONNECTION, REDIS_HOST },
};

pub mod account;
pub mod totp;
pub mod auth;
pub mod sudo;
pub mod mfa_login;

pub struct Database {
    pub account: AccountOperations,
    pub totp: TotpOperations,
    pub auth: AuthOperations,
    pub mfa_login: MfaLoginOperations,
    pub sudo: SudoOperations,
}

impl Database {
    pub async fn default() -> Result<Self, mongodb::error::Error> {
        tracing::info!("Connecting to mongodb...");
        let mongo_client = mongodb::Client::with_uri_str(&*MONGODB_CONNECTION).await.unwrap();
        let mongo_database = mongo_client.database("koii");

        tracing::info!("Connecting to redis...");
        let redis_client = redis::Client
            ::open(&**REDIS_HOST)
            .unwrap()
            .get_multiplexed_async_connection().await
            .unwrap();

        let account_collection = mongo_database.collection("account");
        let totp_collection = mongo_database.collection("totp");
        let totp_code_collection = mongo_database.collection("totp_code");
        let auth_collection = mongo_database.collection("auth");
        let mfa_login_collection = mongo_database.collection("mfa_login");
        let sudo_collection = mongo_database.collection("sudo");

        Ok(Database {
            account: AccountOperations::new(account_collection).await.unwrap(),
            totp: TotpOperations {
                store: TotpStoreOperations::new(
                    totp_collection,
                    mongo_client.clone()
                ).await.unwrap(),
                code: TotpUsedCodeOperations::new(totp_code_collection).await.unwrap(),
            },
            auth: AuthOperations::new(auth_collection, redis_client.clone()).await.unwrap(),
            mfa_login: MfaLoginOperations::new(mfa_login_collection).await.unwrap(),
            sudo: SudoOperations::new(sudo_collection).await.unwrap(),
        })
    }
}
