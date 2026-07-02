use axum::{
    Extension,
    Json,
    extract::State,
    http::{ StatusCode, header::SET_COOKIE },
    response::AppendHeaders,
};
use nanoid::nanoid;
use serde::{ Deserialize, Serialize };
use validator::Validate;

use crate::{
    base::{ self, cookies, response::ResponseModel },
    env::{ ACCOUNT_TOKEN_IDENTIFIER_LENGTH, PARTIAL_LOGIN_MAX_AGE, REFRESH_MAX_AGE, TOKEN_MAX_AGE },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    utils::{ jwt::{ KeyClaims, KeyKind }, timestamp },
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
    pub partial_login: Option<String>,
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

    let account = match state.app.db.account.get_from_email(&payload.email).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return base::response::error(StatusCode::NOT_FOUND, "Wrong email or password.", None);
        }
        Err(error) => {
            tracing::error!("Unable to retreive account for {}: {}", payload.email, error);
            return base::response::internal_error(None);
        }
    };

    let verify_pass_request = VerifyPassRequest {
        password: payload.password,
        hash: account.password_hash,
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

    let issued_at = timestamp::now();
    let identifier = nanoid!(*ACCOUNT_TOKEN_IDENTIFIER_LENGTH);

    match account.mfa_status.has_mfa() {
        false => {}
        true => {
            let signed_partial_login = state.app.jwt.generate(KeyClaims {
                account_id: account.account_id,
                identifier,
                kind: KeyKind::PartialLogin,
                iat: issued_at,
                exp: issued_at + *PARTIAL_LOGIN_MAX_AGE,
            });

            return base::response::result(
                StatusCode::OK,
                LoginResponse { partial_login: Some(signed_partial_login) },
                None
            );
        }
    }

    let signed_token = state.app.jwt.generate(KeyClaims {
        account_id: account.account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Authentication,
        iat: issued_at,
        exp: issued_at + *TOKEN_MAX_AGE,
    });

    let signed_refresh = state.app.jwt.generate(KeyClaims {
        account_id: account.account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Refresh,
        iat: issued_at,
        exp: issued_at + *REFRESH_MAX_AGE,
    });

    match state.app.db.auth.clone().issue(account.account_id.clone(), identifier, issued_at).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!("A nanoid collision was found.");
            return base::response::error(
                StatusCode::CONFLICT,
                "Thank you for being this rare.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Unable to issue a token for {}: {}", account.account_id, error);
            return base::response::internal_error(None);
        }
    }

    let token_cookie = cookies::construct("token", signed_token, "/", *TOKEN_MAX_AGE);
    let refresh_cookie = cookies::construct(
        "refresh",
        signed_refresh,
        "/account/refresh",
        *REFRESH_MAX_AGE
    );

    base::response::result(
        StatusCode::OK,
        LoginResponse { partial_login: None },
        Some(AppendHeaders(vec![(SET_COOKIE, token_cookie), (SET_COOKIE, refresh_cookie)]))
    )
}
