use mongodb::{
    ClientSession,
    Collection,
    IndexModel,
    bson,
    error::WriteFailure,
    options::IndexOptions,
};
use serde::{ Deserialize, Serialize };
use totp_rs::TOTP;

#[derive(Clone, Deserialize, Serialize)]
pub struct TotpStoreDocument {
    /// Unique ID to the account.
    pub account_id: String,
    pub totp: TOTP,
}

#[derive(Clone)]
pub struct TotpStoreOperations {
    collection: Collection<TotpStoreDocument>,
    mongo_client: mongodb::Client,
}

impl TotpStoreOperations {
    pub async fn new(
        collection: Collection<TotpStoreDocument>,
        mongo_client: mongodb::Client
    ) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        Ok(TotpStoreOperations { collection, mongo_client })
    }

    /// This method performs a transaction between `account` and `totp` collection, hence
    /// the need for the additional of mongodb client and account collection.
    pub async fn add(&self, document: TotpStoreDocument) -> Result<bool, mongodb::error::Error> {
        let mut session = self.mongo_client.start_session().await?;

        let result = session.start_transaction().and_run2(async move |session: &mut ClientSession| {
            let collection = session
                .client()
                .database("koii")
                .collection::<TotpStoreDocument>("totp");
            let account_collection = session
                .client()
                .database("koii")
                .collection::<TotpStoreDocument>("account");

            collection.insert_one(&document).session(&mut *session).await?;
            let result = account_collection
                .update_one(
                    bson::doc! { "account_id": &document.account_id },
                    bson::doc! {
                        "$set": {
                            "mfa_status.totp": true
                        }
                    }
                )
                .session(session).await?;
            Ok(result.modified_count == 1)
        }).await;

        return match result {
            Ok(modified) => Ok(modified),
            Err(error) => {
                match *error.kind {
                    mongodb::error::ErrorKind::Write(WriteFailure::WriteError(ref write_error)) if
                        write_error.code == 11000
                    => Ok(false),
                    _ => Err(error),
                }
            }
        };
    }

    pub async fn get_from_account(
        &self,
        account_id: &str
    ) -> Result<Option<TOTP>, mongodb::error::Error> {
        let totp_collection = self.collection.find_one(
            bson::doc! { "account_id": account_id }
        ).await?;

        match totp_collection {
            Some(totp_collection) => Ok(Some(totp_collection.totp)),
            None => Ok(None),
        }
    }

    pub async fn delete(&self, account_id: String) -> Result<bool, mongodb::error::Error> {
        let mut session = self.mongo_client.start_session().await?;

        session.start_transaction().and_run2(async move |session: &mut ClientSession| {
            let account_id = account_id.clone();

            let database = session.client().database("koii");

            let collection = database.collection::<TotpStoreDocument>("totp");
            let account_collection = database.collection::<TotpStoreDocument>("account");

            collection
                .delete_one(bson::doc! { "account_id": &account_id })
                .session(&mut *session).await?;
            account_collection
                .update_one(
                    bson::doc! { "account_id": &account_id },
                    bson::doc! {
                        "$set": {
                            "mfa_status.totp": false
                        }
                    }
                )
                .session(session).await?;
            Ok(())
        }).await?;

        Ok(true)
    }
}
