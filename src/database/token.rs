use mongodb::{
    Collection,
    IndexModel,
    bson,
    error::WriteFailure,
    options::{ CountOptions, IndexOptions },
};
use redis::{ AsyncCommands, RedisError, aio::MultiplexedConnection };
use serde::{ Deserialize, Serialize };
use thiserror::Error;

use crate::{ env::REFRESH_MAX_AGE, utils::jwt::{ TokenClaims, TokenKind } };

#[derive(Deserialize, Serialize)]
pub struct TokenDocument {
    /// Unique ID to the account.
    pub account_id: String,

    /// The token's identifier.
    pub identifier: String,

    /// TTL: REFRESH_MAX_AGE
    pub created_at: bson::DateTime,
}

#[derive(Error, Debug)]
pub enum TokenOperationError {
    #[error("Bad database")] Database(#[from] mongodb::error::Error),
    #[error("Bad bson")] Bson(#[from] mongodb::bson::error::Error),
    #[error("Bad cache")] Cache(#[from] RedisError),
}

#[derive(Clone)]
pub struct TokenOperations {
    collection: Collection<TokenDocument>,
    cache: MultiplexedConnection,
}
impl TokenOperations {
    pub async fn new(
        collection: Collection<TokenDocument>,
        cache: MultiplexedConnection
    ) -> Result<Self, TokenOperationError> {
        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "account_id": 1, "identifier": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build()
        ).await?;

        collection.create_index(
            IndexModel::builder()
                .keys(bson::doc! { "created_at": 1 })
                .options(IndexOptions::builder().expire_after(*REFRESH_MAX_AGE).build())
                .build()
        ).await?;

        Ok(TokenOperations { collection, cache })
    }

    /// Add token to cache and database.
    pub async fn issue(&mut self, claims: TokenClaims) -> Result<bool, TokenOperationError> {
        if let TokenKind::AUTHENTICATION = claims.kind {
            tracing::warn!("The token claims used for creating a store is not a refresh token.");
        }

        let cache_key = format!("account:{}:token:{}", &claims.account_id, &claims.identifier);

        // Add database entry as a fallback.
        let result = self.collection.insert_one(TokenDocument {
            account_id: claims.account_id,
            identifier: claims.identifier,
            created_at: bson::DateTime::from_millis(
                ((claims.exp - REFRESH_MAX_AGE.as_secs()) * 1000) as i64
            ),
        }).await;

        match result {
            Ok(_) => {}
            Err(error) => {
                match *error.kind {
                    mongodb::error::ErrorKind::Write(WriteFailure::WriteError(ref write_error)) if
                        write_error.code == 11000
                    => {
                        return Ok(false);
                    }
                    _ => {
                        return Err(TokenOperationError::Database(error));
                    }
                }
            }
        }

        // Preload cache.
        redis
            ::cmd("SET")
            .arg(&cache_key)
            .arg(true)
            .arg("EX")
            .arg(REFRESH_MAX_AGE.as_secs())
            .exec_async(&mut self.cache).await?;

        Ok(true)
    }

    pub async fn authorize(&mut self, claims: &TokenClaims) -> Result<bool, TokenOperationError> {
        let status = self.cache.get::<String, Option<bool>>(
            format!("account:{}:token:{}", claims.account_id, claims.identifier)
        ).await?;

        return match status {
            Some(status) => Ok(status),
            None => self.refetch(claims).await,
        };
    }

    pub async fn revoke(&mut self, claims: &TokenClaims) -> Result<bool, TokenOperationError> {
        self.cache.set::<String, bool, String>(
            format!("account:{}:token:{}", &claims.account_id, &claims.identifier),
            false
        ).await?;

        let db_result = self.collection.delete_one(
            bson::doc! { "account_id": &claims.account_id, "identifier": &claims.identifier }
        ).await?;

        Ok(db_result.deleted_count == 1)
    }

    pub async fn revoke_all(&mut self, account_id: &str) -> Result<u64, TokenOperationError> {
        let mut tokens_cursor = self.collection.find(
            bson::doc! { "account_id": account_id }
        ).await?;

        // Loop through database to batch a cache request for all tokens.
        let mut mset_props: Vec<(String, bool)> = Vec::new();
        while tokens_cursor.advance().await? {
            let token_doc: TokenDocument = bson::deserialize_from_slice(
                tokens_cursor.current().as_bytes()
            )?;

            mset_props.push((
                format!("account:{}:token:{}", &token_doc.account_id, &token_doc.identifier),
                false,
            ));
        }

        let db_result = self.collection.delete_many(bson::doc! { "account_id": account_id }).await?;

        self.cache.mset::<_, _, String>(&mset_props).await?;

        Ok(db_result.deleted_count)
    }

    /// Cache miss, ask the database instead if this token is valid or not.
    async fn refetch(&mut self, claims: &TokenClaims) -> Result<bool, TokenOperationError> {
        tracing::info!("Cache miss on account: {}", &claims.account_id);
        let exists = self.collection
            .count_documents(
                bson::doc! { "account_id": &claims.account_id, "identifier": &claims.identifier }
            )
            .with_options(CountOptions::builder().limit(1).build()).await?;

        let cache_key = format!("account:{}:token:{}", claims.account_id, claims.identifier);

        redis
            ::cmd("SET")
            .arg(&cache_key)
            .arg(exists == 1)
            .arg("EX")
            .arg(REFRESH_MAX_AGE.as_secs())
            .exec_async(&mut self.cache).await?;

        Ok(exists == 1)
    }
}
