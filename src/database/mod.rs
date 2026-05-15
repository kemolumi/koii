use crate::{
    database::{
        account::AccountOperations,
        sudo::SudoOperations,
        token::TokenOperations,
        totp::TotpOperations,
        totp_code::TotpCodeOperations,
    },
    env::{ MONGODB_CONNECTION, REDIS_HOST },
};

pub mod account;
pub mod totp;
pub mod totp_code;
pub mod token;
pub mod sudo;
pub mod passkey;

pub struct Database {
    pub account: AccountOperations,
    pub totp: TotpOperations,
    pub totp_code: TotpCodeOperations,
    pub token: TokenOperations,
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
        let token_collection = mongo_database.collection("token");
        let sudo_collection = mongo_database.collection("sudo");

        Ok(Database {
            account: AccountOperations::new(account_collection).await.unwrap(),
            totp: TotpOperations::new(totp_collection).await.unwrap(),
            totp_code: TotpCodeOperations::new(totp_code_collection).await.unwrap(),
            token: TokenOperations::new(token_collection, redis_client.clone()).await.unwrap(),
            sudo: SudoOperations::new(sudo_collection).await.unwrap(),
        })
    }
}
