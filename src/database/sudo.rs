use mongodb::{
    Collection,
    IndexModel,
    bson,
    error::WriteFailure,
    options::{ CountOptions, IndexOptions },
};
use serde::{ Deserialize, Serialize };

use crate::env::SUDO_MAX_AGE;

#[derive(Serialize, Deserialize)]
pub struct SudoDocument {
    /// Unique ID to the account.
    pub account_id: String,

    /// The token's identifier.
    pub identifier: String,

    /// TTL: SUDO_MAX_AGE
    pub created_at: bson::DateTime,
}

pub struct SudoOperations {
    collection: Collection<SudoDocument>,
}

impl SudoOperations {
    pub async fn new(collection: Collection<SudoDocument>) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1, "identifier": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "created_at": 1 })
                .options(IndexOptions::builder().expire_after(*SUDO_MAX_AGE).build())
                .build()
        ).await?;

        Ok(SudoOperations { collection })
    }

    /// Using the current account token and allows it to be used for destructive operations.
    pub async fn elevate(&self, document: &SudoDocument) -> Result<bool, mongodb::error::Error> {
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

    pub async fn authorize(
        &self,
        account_id: &str,
        identifier: String
    ) -> Result<bool, mongodb::error::Error> {
        let exists = self.collection
            .count_documents(bson::doc! { "account_id": account_id, "identifier": identifier })
            .with_options(CountOptions::builder().limit(1).build()).await?;

        Ok(exists == 1)
    }
}
