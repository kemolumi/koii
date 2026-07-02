use axum::{ Extension, Json, extract::State, http::StatusCode };
use mongodb::bson;
use serde::Deserialize;
use validator::Validate;

use crate::{
    base::{ self, response::ResponseModel },
    database::{ mfa_login::MfaLoginDocument, totp::code::TotpUsedCodeDocument },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    utils::jwt::KeyKind,
};

#[derive(Deserialize, Validate, Clone)]
pub struct UpgradePayload {
    #[validate(length(equal = 6))]
    pub totp_code: String,
    pub mfa_login: String,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<UpgradePayload>
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
        Err(_) => {
            return base::response::error(
                StatusCode::BAD_REQUEST,
                "TOTP code must be 6 characters.",
                None
            );
        }
    }

    let Some(token) = state.app.jwt.verify(&payload.mfa_login, KeyKind::MfaLogin) else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    let totp = match state.app.db.totp.store.get_from_account(&token.account_id).await {
        Ok(Some(totp)) => totp,
        Ok(None) => {
            return base::response::error(
                StatusCode::NOT_FOUND,
                "No TOTP method was found for this account.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Can't fetch TOTP struct for {}: {error}", &token.account_id);
            return base::response::internal_error(None);
        }
    };

    match totp.check_current(&payload.totp_code) {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(StatusCode::UNAUTHORIZED, "Wrong TOTP code.", None);
        }
        Err(error) => {
            tracing::error!("Verify TOTP failed for {}: {error}", &token.account_id);
            return base::response::internal_error(None);
        }
    }

    let totp_used = TotpUsedCodeDocument {
        account_id: token.account_id,
        code: payload.totp_code,
        used_at: bson::DateTime::now(),
    };

    match state.app.db.totp.code.consume(&totp_used).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(StatusCode::UNAUTHORIZED, "Wrong TOTP code.", None);
        }
        Err(error) => {
            tracing::error!("Can't use TOTP code for {}: {error}", &totp_used.account_id);
            return base::response::internal_error(None);
        }
    }

    let consume_document = MfaLoginDocument {
        account_id: totp_used.account_id.clone(),
        identifier: token.identifier,
        issued_at: bson::DateTime::from_millis(token.iat.as_millis() as i64),
    };

    match state.app.db.mfa_login.consume(&consume_document).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
        }
        Err(error) => {
            tracing::error!(
                "Failed to consume `MfaToken` token for {}: {error}",
                consume_document.account_id
            );
            return base::response::internal_error(None);
        }
    }

    let headers = match
        base::auth::quick_issue(
            &state.app.db.auth,
            &state.app.jwt,
            consume_document.account_id
        ).await
    {
        Ok(headers) => headers,
        Err(bad) => {
            return bad;
        }
    };

    base::response::success(StatusCode::OK, Some(headers))
}
