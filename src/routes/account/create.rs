use serde::Deserialize;
use axum::{ Extension, Json, extract::State, http::StatusCode };
use mongodb::{ bson::{ self, doc } };
use validator::Validate;

use crate::{
    base::{ self, response::ResponseModel },
    env::{ ACCOUNT_ID_LENGTH, EMAIL_VERIFY_CODE_LENGTH },
    database::account::AccountDocument,
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    workers::verify_email::VerifyEmailRequest,
};
use nanoid::nanoid;

#[derive(Deserialize, Validate, Clone)]
pub struct CreatePayload {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12))]
    pub password: String,
    #[validate(length(max = 2048))]
    pub clientstile: String,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<CreatePayload>
) -> ResponseModel {
    if authorization_info.active {
        return base::response::error(
            StatusCode::FORBIDDEN,
            "There's already an active account.",
            None
        );
    }

    match payload.validate() {
        Ok(_) => {} // Valid payload, passing down.
        Err(field) => {
            if let Some(field) = field.errors().iter().next() {
                return base::response::error(
                    StatusCode::BAD_REQUEST,
                    &format!("At least one field is not satisfied: {}", field.0),
                    None
                );
            }
            return base::response::internal_error(None);
        }
    }

    match state.app.turnstile.verify(payload.clientstile, state.app.debug).await {
        Ok(true) => {} // Turnstile verified, passing down.
        Ok(false) => {
            return base::response::error(
                StatusCode::BAD_REQUEST,
                "Something went wrong, try refresh the page and enter information again.",
                None
            );
        }
        Err(_) => {
            tracing::error!("Can't contact Turnstile to verify the code when creating an account.");
            return base::response::internal_error(None);
        }
    }

    match state.app.db.account.get_from_email(&payload.email).await {
        Ok(None) => {} // Account not found at this point, passing down to do hash.
        Ok(Some(_)) => {
            return base::response::error(StatusCode::CONFLICT, "Email already registered.", None);
        }
        Err(error) => {
            tracing::error!("Database failed to find {}: {}", &payload.email, error);
            return base::response::internal_error(None);
        }
    }

    let account_id = nanoid!(*ACCOUNT_ID_LENGTH);
    let verify_code = if !state.app.debug {
        nanoid!(*EMAIL_VERIFY_CODE_LENGTH)
    } else {
        "debug".to_string()
    };
    let password_hash = match state.app.worker.hash_pass.send(payload.password).await {
        Ok(Some(hash)) => hash,
        _ => {
            tracing::error!("Hash password worker failed when creating an account.");
            return base::response::internal_error(None);
        }
    };

    let account = AccountDocument {
        account_id: account_id.clone(),
        email: payload.email.clone(),
        password_hash,
        verify_requested: Some(bson::DateTime::now()),
        verify_code: Some(verify_code.clone()),
        created_at: None,
        deleted: None,
    };

    match state.app.db.account.add(&account).await {
        Ok(true) => {} // Account added, passing down.
        Ok(false) => {
            return base::response::error(StatusCode::CONFLICT, "Email already registered.", None);
        }
        Err(error) => {
            tracing::error!("Database failed to store {}: {}", &payload.email, error);
            return base::response::internal_error(None);
        }
    }

    match
        state.app.worker.verify_email.send_ignore(VerifyEmailRequest {
            email: payload.email,
            verify_code,
        }).await
    {
        Ok(_) => {} // Send email successful, passing down.
        Err(_) => {
            tracing::error!(
                "Email worker failed to deliver the verification link for {}.",
                account_id
            );
            return base::response::internal_error(None);
        }
    }

    base::response::result(
        StatusCode::CREATED,
        "Check your inbox to verify your email!".into(),
        None
    )
}
