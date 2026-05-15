use axum::{
    Extension,
    Json,
    extract::State,
    http::{ StatusCode, header::SET_COOKIE },
    response::AppendHeaders,
};
use mongodb::bson;
use serde::Deserialize;
use validator::Validate;

use crate::{
    base::{ self, cookies, response::ResponseModel },
    database::totp_code::TotpCodeDocument,
    env::{ REFRESH_MAX_AGE, TOKEN_MAX_AGE },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    workers::verify_pass::VerifyPassRequest,
};

#[derive(Deserialize, Validate, Clone)]
pub struct LoginPayload {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12))]
    pub password: String,
    #[validate(length(equal = 6))]
    pub totp_code: Option<String>,
    #[validate(length(max = 2048))]
    pub clientstile: String,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<LoginPayload>
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

    let account = state.app.db.account.get_from_email(&payload.email).await;
    let account = match account {
        Ok(Some(account)) => account,
        Ok(None) => {
            return base::response::error(StatusCode::NOT_FOUND, "Wrong email or password.", None);
        }
        Err(error) => {
            tracing::error!("Unable to retreive account for {}: {}", payload.email, error);
            return base::response::internal_error(None);
        }
    };

    match
        state.app.worker.verify_pass.send(VerifyPassRequest {
            password: payload.password,
            hash: account.password_hash,
        }).await
    {
        Ok(Some(true)) => {} // Password match, passing down.
        Ok(Some(false)) => {
            return base::response::error(StatusCode::NOT_FOUND, "Wrong email or password.", None);
        }
        _ => {
            tracing::error!("Verify password worker failure.");
            return base::response::internal_error(None);
        }
    }

    match account.verify_requested {
        None => {} // Account not in verify process, passing down.
        Some(_) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "This account is pending for verification, please check your email.",
                None
            );
        }
    }

    match account.deleted {
        None => {} // Account not marked for deletion, passing down.
        Some(_) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "This account is pending for deletion, please recover this account.",
                None
            );
        }
    }

    match state.app.db.totp.get(&account.account_id).await {
        Ok(None) => {} // No TOTP, passing down.
        Ok(Some(totp)) => {
            let Some(totp_code) = payload.totp_code else {
                return base::response::error(StatusCode::FORBIDDEN, "TOTP Required.".into(), None);
            };

            match totp.verify(&totp_code) {
                Ok(true) => {} // Correct TOTP code, passing down.
                Ok(false) => {
                    return base::response::error(
                        StatusCode::UNAUTHORIZED,
                        "Wrong TOTP code.",
                        None
                    );
                }
                Err(_) => {
                    return base::response::internal_error(None);
                }
            }

            let entry = TotpCodeDocument {
                account_id: account.account_id.clone(),
                code: totp_code,
                created_at: bson::DateTime::now(),
            };

            match state.app.db.totp_code.use_code(&entry).await {
                Ok(true) => {} // New TOTP code used, passing down.
                Ok(false) => {
                    return base::response::error(
                        StatusCode::UNAUTHORIZED,
                        "Wrong TOTP code.",
                        None
                    );
                }
                Err(error) => {
                    tracing::error!("Use TOTP failed: {error}");
                    return base::response::internal_error(None);
                }
            }
        }
        Err(error) => {
            tracing::error!("Failed to retreive TOTP: {error}");
            return base::response::internal_error(None);
        }
    }

    let pair = state.app.jwt.generate(&account.account_id);

    match state.app.db.auth.clone().issue(pair.token.0, pair.created_at).await {
        Ok(true) => {} // Token stored to db, passing down.
        Ok(false) => {
            tracing::error!("Gem alert {}.", &account.account_id);
            return base::response::error(
                StatusCode::CONFLICT,
                "Thank you for being this rare.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Unable to issue a token for {}: {}", &account.account_id, error);
            return base::response::internal_error(None);
        }
    }

    let token_cookie = cookies::construct("token", pair.token.1, "/", *TOKEN_MAX_AGE);
    let refresh_cookie = cookies::construct(
        "refresh",
        pair.refresh.1,
        "/account/refresh_token",
        *REFRESH_MAX_AGE
    );

    base::response::success(
        StatusCode::OK,
        Some(AppendHeaders(vec![(SET_COOKIE, token_cookie), (SET_COOKIE, refresh_cookie)]))
    )
}
