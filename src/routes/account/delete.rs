use axum::{
    Extension,
    extract::State,
    http::{ StatusCode, header::SET_COOKIE },
    response::AppendHeaders,
};

use crate::{
    base::{ self, cookies, response::ResponseModel },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
};

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>
) -> ResponseModel {
    let Some(token) = authorization_info.token else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    // Safely remove the account first, if fail, don't remove token.
    match state.app.db.account.mark_deletion(&token.account_id).await {
        Ok(_) => {}
        Err(error) => {
            tracing::error!("Unable to mark deletion for {}: {}", token.account_id, error);
            return base::response::internal_error(None);
        }
    }

    // Account now gone, delete tokens in cache.
    match state.app.db.auth.revoke_all(&token.account_id).await {
        Ok(_) => {}
        Err(error) => {
            tracing::error!("Unable to revoke all tokens for {}: {}", &token.account_id, error);
            return base::response::internal_error(None);
        }
    }

    base::response::success(
        StatusCode::OK,
        Some(
            AppendHeaders(
                vec![
                    (SET_COOKIE, cookies::remove("token", "/")),
                    (SET_COOKIE, cookies::remove("refresh", "/account/refresh"))
                ]
            )
        )
    )
}
