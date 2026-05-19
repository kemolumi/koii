use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use serde::{ Deserialize, Serialize };

use crate::utils::totp::Totp;

#[derive(Deserialize, Serialize)]
pub struct TotpStoreDocument {
    /// Unique ID to the account.
    pub account_id: String,
    pub totp: Totp,
}

pub struct TotpStoreOperations {
    collection: Collection<TotpStoreDocument>,
}

impl TotpStoreOperations {
    pub async fn new(
        collection: Collection<TotpStoreDocument>
    ) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        Ok(TotpStoreOperations { collection })
    }

    pub async fn add(&self, document: &TotpStoreDocument) -> Result<bool, mongodb::error::Error> {
        match self.collection.insert_one(document).await {
            Ok(_) => {}
            Err(error) => {
                match *error.kind {
                    mongodb::error::ErrorKind::Write(WriteFailure::WriteError(ref write_error)) if
                        write_error.code == 11000
                    => {
                        return Ok(false);
                    }
                    _ => {
                        return Err(error);
                    }
                }
            }
        }

        Ok(true)
    }

    pub async fn get_from_account(
        &self,
        account_id: &str
    ) -> Result<Option<Totp>, mongodb::error::Error> {
        let totp_collection = self.collection.find_one(
            bson::doc! { "account_id": account_id }
        ).await?;

        match totp_collection {
            Some(totp_collection) => Ok(Some(totp_collection.totp)),
            None => Ok(None),
        }
    }

    pub async fn delete(&self, account_id: &str) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.delete_one(bson::doc! { "account_id": account_id }).await?;

        Ok(result.deleted_count == 1)
    }
}
