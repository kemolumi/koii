use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use serde::{ Deserialize, Serialize };

use crate::env::TOTP_CODE_VOID_WINDOW;

#[derive(Deserialize, Serialize)]
pub struct TotpUsedCodeDocument {
    /// Unique ID to the account.
    pub account_id: String,
    pub code: String,
    pub created_at: bson::DateTime,
}

pub struct TotpUsedCodeOperations {
    collection: Collection<TotpUsedCodeDocument>,
}

impl TotpUsedCodeOperations {
    pub async fn new(
        collection: Collection<TotpUsedCodeDocument>
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

        Ok(TotpUsedCodeOperations { collection })
    }

    /// This is a DB operation for ensuring that the TOTP code isn't replayed,
    /// **NOT** a way to verify TOTP and put it in a database at the same time,
    /// do it yourself before putting it in.
    pub async fn consume(
        &self,
        document: &TotpUsedCodeDocument
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
