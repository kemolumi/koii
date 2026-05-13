use axum::{ Extension, Json, extract::State };
use reqwest::StatusCode;
use serde::Deserialize;
use validator::{ Validate, ValidationErrorsKind };

use crate::{
    base::{ self, response::ResponseModel },
    database::totp::TotpDocument,
    middlewares::auth::{ AuthorizationInfo, AuthorizationStatus },
    routes::account::AccountRoutesState,
    utils::totp::Totp,
};

#[derive(Deserialize, Validate)]
pub struct CreatePayload {
    #[validate(length(max = 32))]
    #[validate(does_not_contain(pattern = ";"))]
    name: String,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<CreatePayload>
) -> ResponseModel {
    match authorization_info.status {
        AuthorizationStatus::Authorized => {} // Authorized, passing down.
        _ => {
            return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
        }
    }

    match payload.validate() {
        Ok(_) => {} // Valid payload, passing down.
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
                        "The name for the TOTP is too long (32 characters max).",
                        None
                    );
                }
                std::borrow::Cow::Borrowed("does_not_contain") => {
                    return base::response::error(
                        StatusCode::BAD_REQUEST,
                        "The name for the TOTP must not contains the character \";\"",
                        None
                    );
                }
                _ => {
                    return base::response::internal_error(None);
                }
            }
        }
    }

    let Some(token) = authorization_info.token else {
        return base::response::internal_error(None);
    };

    let totp = match Totp::new(payload.name) {
        Ok(totp) => totp,
        Err(_) => {
            return base::response::internal_error(None);
        }
    };

    let document = TotpDocument {
        totp,
        account_id: token.account_id,
    };

    match state.app.db.totp.add(&document).await {
        Ok(true) => {} // TOTP added, passing down.
        Ok(false) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "There is an exisiting TOTP. Please delete it first.",
                None
            );
        }
        Err(_) => {
            return base::response::internal_error(None);
        }
    }

    base::response::result(StatusCode::CREATED, document.totp.url.into(), None)
}
