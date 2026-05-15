use axum::{ Extension, extract::State, response::AppendHeaders };
use reqwest::{ StatusCode, header::SET_COOKIE };

use crate::{
    base::{ self, cookies, response::ResponseModel },
    env::{ REFRESH_MAX_AGE, TOKEN_MAX_AGE },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
};

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>
) -> ResponseModel {
    let Some(revoking_refresh) = authorization_info.refresh else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    let pair = state.app.jwt.generate(&revoking_refresh.account_id);

    match state.app.db.auth.clone().issue(pair.token.0, pair.created_at).await {
        Ok(true) => {} // New token pushed into databse, passing down.
        Ok(false) => {
            tracing::error!(
                "Tried adding new identifier for {}, but found in database, which is rare af if you ask me.",
                revoking_refresh.account_id
            );
            return base::response::internal_error(None);
        }
        Err(_) => {
            tracing::error!(
                "Can't push a new token into database for {}",
                revoking_refresh.account_id
            );
            return base::response::internal_error(None);
        }
    }

    match
        state.app.db.auth
            .clone()
            .revoke(&revoking_refresh.account_id, &revoking_refresh.identifier).await
    {
        Ok(true) => {} // Token revoked, passing down.
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

    let token_cookie = cookies::construct("token", pair.token.1, "/", *TOKEN_MAX_AGE);
    let refresh_cookie = cookies::construct(
        "refresh",
        pair.refresh.1,
        "/account/refresh",
        *REFRESH_MAX_AGE
    );

    base::response::success(
        StatusCode::OK,
        Some(AppendHeaders(vec![(SET_COOKIE, token_cookie), (SET_COOKIE, refresh_cookie)]))
    )
}
