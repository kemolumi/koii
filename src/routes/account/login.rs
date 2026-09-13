use axum::{ Extension, Json, extract::State, http::StatusCode };
use nanoid::nanoid;
use serde::{ Deserialize, Serialize };
use validator::Validate;

use crate::{
    base::{ self, response::ResponseModel },
    env::{ ACCOUNT_TOKEN_IDENTIFIER_LENGTH, MFA_LOGIN_MAX_AGE },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    types::{ AccountId, EmailAddress, Identifier, JwtString },
    utils::jwt::{ KeyClaims, KeyKind },
    workers::verify_pass::VerifyPassRequest,
};

#[derive(Deserialize, Validate, Clone)]
pub struct LoginPayload {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12))]
    pub password: String,
    #[validate(length(max = 2048))]
    pub turnstile_token: String,
}

#[derive(Serialize, Validate, Clone)]
pub struct LoginResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_login: Option<JwtString>,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<LoginPayload>
) -> ResponseModel<LoginResponse> {
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

    let email = EmailAddress::new(payload.email);

    let account = match state.app.db.account.get_from_email(&email).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return base::response::error(StatusCode::NOT_FOUND, "Wrong email or password.", None);
        }
        Err(error) => {
            tracing::error!("Unable to retreive account for {}: {}", email, error);
            return base::response::internal_error(None);
        }
    };

    let verify_pass_request = VerifyPassRequest {
        password: payload.password.into(),
        hash: account.password_hash.into(),
    };

    match state.app.worker.verify_pass.send(verify_pass_request).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(StatusCode::NOT_FOUND, "Wrong email or password.", None);
        }
        Err(error) => {
            tracing::error!("Verify password worker failure for {}: {error}", account.account_id);
            return base::response::internal_error(None);
        }
    }

    match account.verify_requested {
        None => {}
        Some(_) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "This account is pending for verification, please check your email.",
                None
            );
        }
    }

    match account.deletion_requested {
        None => {}
        Some(_) => {
            return base::response::error(
                StatusCode::FORBIDDEN,
                "This account is pending for deletion, please recover this account.",
                None
            );
        }
    }

    let account_id = AccountId::new(account.account_id);

    match account.mfa_status.has_mfa() {
        false => {}
        true => {
            let issued_at = base::timestamp::now();
            let identifier = Identifier::new(nanoid!(*ACCOUNT_TOKEN_IDENTIFIER_LENGTH));

            let signed_mfa_login = state.app.jwt.generate(KeyClaims {
                account_id,
                identifier,
                kind: KeyKind::MfaLogin,
                iat: issued_at,
                exp: issued_at + *MFA_LOGIN_MAX_AGE,
            });

            return base::response::result(
                StatusCode::CREATED,
                LoginResponse { mfa_login: Some(signed_mfa_login) },
                None
            );
        }
    }

    let headers = match
        base::auth::quick_issue(&state.app.db.auth, &state.app.jwt, account_id).await
    {
        Ok(headers) => headers,
        Err(bad) => {
            return bad;
        }
    };

    base::response::success(StatusCode::OK, Some(headers))
}
