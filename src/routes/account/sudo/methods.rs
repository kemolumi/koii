use axum::{ Extension, extract::State, http::StatusCode };
use serde::{ Deserialize, Serialize };

use crate::{
    base::{ self, response::ResponseModel },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
};

#[derive(Serialize, Deserialize)]
pub struct SudoMethodsResponse {
    email: bool,
    totp: bool,
    passkey: bool,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>
) -> ResponseModel<SudoMethodsResponse> {
    let Some(token) = authorization_info.token else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    let account = match state.app.db.account.get_active_from_id(&token.account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return base::response::error(
                StatusCode::NOT_FOUND,
                "The account is currently on hold.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Unable to retreive account for {}: {}", token.account_id, error);
            return base::response::internal_error(None);
        }
    };

    let methods = SudoMethodsResponse {
        email: account.mfa_status.has_mfa(),
        totp: account.mfa_status.totp,
        passkey: account.mfa_status.passkey,
    };

    base::response::result(StatusCode::OK, methods, None)
}
