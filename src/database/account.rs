use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use serde::{ Deserialize, Serialize };

use crate::env::{ EMAIL_VERIFY_EXPIRE, ACCOUNT_DELETE_WINDOW };

#[derive(Deserialize, Serialize)]
pub struct AccountDocument {
    /// Unique ID to the account.
    pub account_id: String,

    /// Account's email.
    pub email: String,

    /// Account's password hash using argon2id.
    pub password_hash: String,

    /// The time when the user verified the account locking in as the creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<bson::DateTime>,

    /// The time when the verify key was sent, this value gets deleted when
    /// the account was verifed.
    ///
    /// TTL: EMAIL_VERIFY_EXPIRE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_requested: Option<bson::DateTime>,

    /// The actual verify code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_code: Option<String>,

    /// Mark the account as deleted when the user request for deletion.
    ///
    /// TTL: ACCOUNT_DELETE_FRAME
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bson::DateTime>,
}

pub struct AccountOperations {
    collection: Collection<AccountDocument>,
}
impl AccountOperations {
    pub async fn new(
        collection: Collection<AccountDocument>
    ) -> Result<Self, mongodb::error::Error> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "email": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "verify_requested": 1 })
                .options(IndexOptions::builder().expire_after(*EMAIL_VERIFY_EXPIRE).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "deleted": 1 })
                .options(IndexOptions::builder().expire_after(*ACCOUNT_DELETE_WINDOW).build())
                .build()
        ).await?;

        Ok(AccountOperations { collection })
    }

    pub async fn add(&self, document: &AccountDocument) -> Result<bool, mongodb::error::Error> {
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

    pub async fn get_from_id(
        &self,
        account_id: &str
    ) -> Result<Option<AccountDocument>, mongodb::error::Error> {
        self.collection.find_one(bson::doc! { "account_id": account_id }).await
    }

    pub async fn get_from_email(
        &self,
        email: &str
    ) -> Result<Option<AccountDocument>, mongodb::error::Error> {
        self.collection.find_one(bson::doc! { "email": email }).await
    }

    pub async fn verify_email(&self, verify_code: &str) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.update_one(
            bson::doc! { "verify_code": verify_code },
            bson::doc! {
                "$set": {
                    "created_at": bson::DateTime::now()
                },
                "$unset": {
                    "verify_requested": "",
                    "verify_code" : ""
                }
            }
        ).await?;

        Ok(result.modified_count == 1)
    }

    pub async fn mark_deletion(&self, account_id: &str) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.update_one(
            bson::doc! { "account_id": account_id },
            bson::doc! { "$set": { "deleted": bson::DateTime::now() } }
        ).await?;

        Ok(result.modified_count == 1)
    }

    pub async fn unmark_deletion(&self, account_id: &str) -> Result<bool, mongodb::error::Error> {
        let result = self.collection.update_one(
            bson::doc! { "account_id": account_id },
            bson::doc! { "$unset": { "deleted": "" } }
        ).await?;

        Ok(result.modified_count == 1)
    }
}
