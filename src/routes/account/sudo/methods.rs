use axum::{ Extension, extract::State, http::StatusCode };
use serde::{ Deserialize, Serialize };

use crate::{
    base::{ self, response::ResponseModel },
    middlewares::auth::{ AuthorizationInfo, AuthorizationStatus },
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
    match authorization_info.status {
        AuthorizationStatus::Authorized => {} // Authorized, passing down.
        _ => {
            return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
        }
    }

    let Some(token) = authorization_info.token else {
        return base::response::internal_error(None);
    };

    let mut methods = SudoMethodsResponse {
        email: true,
        totp: false,
        passkey: false,
    };

    match state.app.db.totp.get(&token.account_id).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            methods.totp = true;
            methods.email = false;
        }
        Err(_) => {
            return base::response::internal_error(None);
        }
    }

    base::response::result(StatusCode::OK, methods, None)
}
