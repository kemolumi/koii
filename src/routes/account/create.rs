use serde::Deserialize;
use axum::{ Extension, Json, extract::State, http::StatusCode };
use mongodb::{ bson::{ self, doc } };
use validator::Validate;

use crate::{
    base::{ self, response::ResponseModel },
    database::account::{ AccountDocument, AccountMfaStatus },
    env::{ ACCOUNT_ID_LENGTH, EMAIL_VERIFY_CODE_LENGTH },
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
    pub turnstile_token: String,
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
        Ok(_) => {}
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

    match state.app.turnstile.verify(payload.turnstile_token).await {
        Ok(true) => {}
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
        Ok(None) => {}
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
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!("Hash password worker failed when creating an account: {error}");
            return base::response::internal_error(None);
        }
    };

    let account = AccountDocument {
        account_id: account_id.clone(),
        email: payload.email.clone(),
        password_hash,
        mfa_status: AccountMfaStatus { totp: false, passkey: false },
        verify_requested: Some(bson::DateTime::now()),
        verify_code: Some(verify_code.clone()),
        issued_at: None,
        deletion_requested: None,
    };

    match state.app.db.account.add(&account).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(StatusCode::CONFLICT, "Email already registered.", None);
        }
        Err(error) => {
            tracing::error!("Database failed to store {}: {}", &payload.email, error);
            return base::response::internal_error(None);
        }
    }

    state.app.worker.verify_email.send_ignore(VerifyEmailRequest {
        email: payload.email,
        verify_code,
    }).await;

    base::response::result(
        StatusCode::CREATED,
        "Check your inbox to verify your email!".into(),
        None
    )
}
