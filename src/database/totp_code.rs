use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use serde::{ Deserialize, Serialize };

use crate::env::TOTP_CODE_VOID_WINDOW;

#[derive(Deserialize, Serialize)]
pub struct TotpCodeDocument {
    /// Unique ID to the account.
    pub account_id: String,
    pub code: String,
    pub created_at: bson::DateTime,
}

pub struct TotpCodeOperations {
    collection: Collection<TotpCodeDocument>,
}

impl TotpCodeOperations {
    pub async fn new(
        collection: Collection<TotpCodeDocument>
    ) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1, "code": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "created_at": 1 })
                .options(IndexOptions::builder().expire_after(Some(*TOTP_CODE_VOID_WINDOW)).build())
                .build()
        ).await?;

        Ok(TotpCodeOperations { collection })
    }

    pub async fn use_code(
        &self,
        document: &TotpCodeDocument
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
