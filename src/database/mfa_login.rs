use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use serde::{ Deserialize, Serialize };

use crate::env::MFA_LOGIN_MAX_AGE;

#[derive(Deserialize, Serialize)]
pub struct MfaLoginDocument {
    /// Unique ID to the account.
    pub account_id: String,
    pub identifier: String,
    pub issued_at: bson::DateTime,
}

pub struct MfaLoginOperations {
    collection: Collection<MfaLoginDocument>,
}

impl MfaLoginOperations {
    pub async fn new(
        collection: Collection<MfaLoginDocument>
    ) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1, "identifier": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "issued_at": 1 })
                .options(IndexOptions::builder().expire_after(*MFA_LOGIN_MAX_AGE).build())
                .build()
        ).await?;

        Ok(MfaLoginOperations { collection })
    }

    pub async fn consume(
        &self,
        document: &MfaLoginDocument
    ) -> Result<bool, mongodb::error::Error> {
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
}
