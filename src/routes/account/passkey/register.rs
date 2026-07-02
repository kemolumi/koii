use axum::{ Extension, Json, extract::State };
use mongodb::bson;
use reqwest::StatusCode;
use serde::Deserialize;
use validator::{ Validate, ValidationErrorsKind };
use webauthn_rs::prelude::{ CreationChallengeResponse, Uuid };

use crate::{
    base::{ self, response::ResponseModel },
    database::passkey::register::PasskeyRegisterDocument,
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
};

#[derive(Deserialize, Validate)]
pub struct CreatePayload {
    #[validate(length(max = 32))]
    #[validate(does_not_contain(pattern = ";"))]
    name: String,
}

#[fastrace::trace]
pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<CreatePayload>
) -> ResponseModel<CreationChallengeResponse> {
    let Some(token) = authorization_info.auth else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    match payload.validate() {
        Ok(_) => {}
        Err(field) => {
            let Some((_, ValidationErrorsKind::Field(validation_errors))) = field
                .errors()
                .iter()
                .next() else {
                return base::response::internal_error(None);
            };

            let Some(validation_error) = validation_errors.get(0) else {
                return base::response::internal_error(None);
            };

            match validation_error.code {
                std::borrow::Cow::Borrowed("length") => {
                    return base::response::error(
                        StatusCode::BAD_REQUEST,
                        "The name for Passkey is too long (32 characters max).",
                        None
                    );
                }
                std::borrow::Cow::Borrowed("does_not_contain") => {
                    return base::response::error(
                        StatusCode::BAD_REQUEST,
                        "The name for Passkey must not contains the character \";\"",
                        None
                    );
                }
                _ => {
                    return base::response::internal_error(None);
                }
            }
        }
    }

    match state.app.db.passkey.store.get_from_account(&token.account_id).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "There is an exisiting Passkey. Please delete it first.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Failed to fetch passkey data for {}: {error}", &token.account_id);
            return base::response::internal_error(None);
        }
    }

    let gid = nanoid::rngs::default(16);
    let passkey_id = Uuid::from_bytes(*gid.as_array().unwrap());

    let passkey_register = match state.app.passkey.register(passkey_id, &payload.name) {
        Ok(register) => register,
        Err(error) => {
            tracing::error!("Error while trying to create passkey register: {error}");
            return base::response::internal_error(None);
        }
    };

    let document = PasskeyRegisterDocument {
        account_id: token.account_id,
        passkey_id,
        register: passkey_register.1,
        issued_at: bson::DateTime::now(),
    };

    match state.app.db.passkey.register.add(&document).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "There is an active Passkey register. Please try again later.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Error while adding passkey register: {error}");
            return base::response::internal_error(None);
        }
    }

    base::response::result(StatusCode::CREATED, passkey_register.0, None)
}
