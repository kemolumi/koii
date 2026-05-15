use mongodb::{ Collection, IndexModel, bson, error::WriteFailure, options::IndexOptions };
use redis::{ AsyncCommands, RedisError, aio::MultiplexedConnection };
use serde::{ Deserialize, Serialize };
use thiserror::Error;

use crate::{ env::{ REFRESH_MAX_AGE, TOKEN_MAX_AGE }, utils::jwt::{ RefreshClaims, TokenClaims } };

/// To invalidate a token pair, just say it's created at the first second of UNIX timestamp.
const INVALIDATE_TIMESTAMP: u64 = 0;

#[derive(Deserialize, Serialize)]
pub struct AuthDocument {
    /// Unique ID to the account.
    pub account_id: String,

    /// The token's identifier.
    pub identifier: String,

    /// TTL: REFRESH_MAX_AGE
    pub created_at: bson::DateTime,
}

#[derive(Error, Debug)]
pub enum AuthOperationError {
    #[error("Bad database")] Database(#[from] mongodb::error::Error),
    #[error("Bad bson")] Bson(#[from] mongodb::bson::error::Error),
    #[error("Bad cache")] Cache(#[from] RedisError),
}

#[derive(Clone)]
pub struct AuthOperations {
    collection: Collection<AuthDocument>,
    cache: MultiplexedConnection,
}
impl AuthOperations {
    pub async fn new(
        collection: Collection<AuthDocument>,
        cache: MultiplexedConnection
    ) -> Result<Self, AuthOperationError> {
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

        Ok(AuthOperations { collection, cache })
    }

    /// Add token to cache and database.
    pub async fn issue(
        &mut self,
        claims: TokenClaims,
        created_at: u64
    ) -> Result<bool, AuthOperationError> {
        let cache_key = format!("account:{}:token:{}", &claims.account_id, &claims.identifier);

        // Add database entry as a fallback.
        let result = self.collection.insert_one(AuthDocument {
            account_id: claims.account_id,
            identifier: claims.identifier,
            created_at: bson::DateTime::from_millis((created_at * 1000) as i64),
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
                        return Err(AuthOperationError::Database(error));
                    }
                }
            }
        }

        // Preload cache.
        redis
            ::cmd("SET")
            .arg(&cache_key)
            .arg(created_at)
            .arg("EX")
            .arg(REFRESH_MAX_AGE.as_secs())
            .exec_async(&mut self.cache).await?;

        Ok(true)
    }

    /// This method assumes that the `TokenClaims` provided is valid and verified by `jsonwebtoken`.
    ///
    /// **DON'T USE THIS METHOD ON AN UNVERIFIED `TokenClaims`.**
    pub async fn check_token(&mut self, claims: &TokenClaims) -> Result<bool, AuthOperationError> {
        let created_at = self.cache.get::<String, Option<u64>>(
            format!("account:{}:token:{}", claims.account_id, claims.identifier)
        ).await?;

        match created_at {
            None => {} // No timestamp found, cache miss.
            Some(created_at) => {
                return Ok(claims.exp - created_at <= TOKEN_MAX_AGE.as_secs());
            }
        }

        let created_at = self.refetch(&claims.account_id, &claims.identifier).await?;
        Ok(claims.exp - created_at <= TOKEN_MAX_AGE.as_secs())
    }

    /// This method assumes that the `RefreshClaims` provided is valid and verified by `jsonwebtoken`.
    ///
    /// **DON'T USE THIS METHOD ON AN UNVERIFIED `RefreshClaims`.**
    pub async fn check_refresh(
        &mut self,
        claims: &RefreshClaims
    ) -> Result<bool, AuthOperationError> {
        let created_at = self.cache.get::<String, Option<u64>>(
            format!("account:{}:token:{}", claims.account_id, claims.identifier)
        ).await?;

        match created_at {
            None => {} // No timestamp found, cache miss.
            Some(created_at) => {
                return Ok(claims.exp - created_at <= REFRESH_MAX_AGE.as_secs());
            }
        }

        // Refill cache, get `created_at` again!
        let created_at = self.refetch(&claims.account_id, &claims.identifier).await?;
        Ok(claims.exp - created_at <= REFRESH_MAX_AGE.as_secs())
    }

    /// Revoke a token, forbidding any actions from the token.
    ///
    /// Used for logout, or invalidating the old refresh token before issuing a new one for `/account/refresh` endpoint.
    pub async fn revoke(
        &mut self,
        account_id: &str,
        identifier: &str
    ) -> Result<bool, AuthOperationError> {
        self.cache.set::<String, bool, String>(
            format!("account:{}:token:{}", account_id, identifier),
            false
        ).await?;

        let db_result = self.collection.delete_one(
            bson::doc! { "account_id": account_id, "identifier": identifier }
        ).await?;

        Ok(db_result.deleted_count == 1)
    }

    pub async fn revoke_all(&mut self, account_id: &str) -> Result<u64, AuthOperationError> {
        let mut tokens_cursor = self.collection.find(
            bson::doc! { "account_id": account_id }
        ).await?;

        // Loop through database to batch a cache request for all tokens.
        let mut mset_props: Vec<(String, u64)> = Vec::new();
        while tokens_cursor.advance().await? {
            let token_doc: AuthDocument = bson::deserialize_from_slice(
                tokens_cursor.current().as_bytes()
            )?;

            mset_props.push((
                format!("account:{}:token:{}", &token_doc.account_id, &token_doc.identifier),
                INVALIDATE_TIMESTAMP,
            ));
        }

        let db_result = self.collection.delete_many(bson::doc! { "account_id": account_id }).await?;

        self.cache.mset::<_, _, String>(&mset_props).await?;

        Ok(db_result.deleted_count)
    }

    /// Cache miss, ask the database instead if this token is valid or not.
    async fn refetch(
        &mut self,
        account_id: &str,
        identifier: &str
    ) -> Result<u64, AuthOperationError> {
        tracing::info!("Cache miss on account: {}", account_id);
        let document = self.collection.find_one(
            bson::doc! { "account_id": account_id, "identifier": identifier }
        ).await?;

        let created_at = match document {
            Some(document) => (document.created_at.timestamp_millis() / 1000) as u64,
            None => INVALIDATE_TIMESTAMP,
        };

        let cache_key = format!("account:{}:token:{}", account_id, identifier);

        // Refill cache.
        redis
            ::cmd("SET")
            .arg(&cache_key)
            .arg(created_at)
            .arg("EX")
            .arg(REFRESH_MAX_AGE.as_secs())
            .exec_async(&mut self.cache).await?;

        Ok(created_at)
    }
}
