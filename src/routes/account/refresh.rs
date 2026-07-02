use axum::{ Extension, extract::State, response::AppendHeaders };
use nanoid::nanoid;
use reqwest::{ StatusCode, header::SET_COOKIE };

use crate::{
    base::{ self, cookies, response::ResponseModel },
    env::{ ACCOUNT_TOKEN_IDENTIFIER_LENGTH, REFRESH_MAX_AGE, TOKEN_MAX_AGE },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
    utils::{ jwt::{ KeyClaims, KeyKind }, timestamp },
};

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>
) -> ResponseModel {
    let Some(revoking_refresh) = authorization_info.refresh else {
        return base::response::error(StatusCode::UNAUTHORIZED, "Get out.", None);
    };

    let issued_at = timestamp::now();
    let identifier = nanoid!(*ACCOUNT_TOKEN_IDENTIFIER_LENGTH);

    let signed_token = state.app.jwt.generate(KeyClaims {
        account_id: revoking_refresh.account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Authentication,
        iat: issued_at,
        exp: issued_at + *TOKEN_MAX_AGE,
    });

    let signed_refresh = state.app.jwt.generate(KeyClaims {
        account_id: revoking_refresh.account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Refresh,
        iat: issued_at,
        exp: issued_at + *REFRESH_MAX_AGE,
    });

    match
        state.app.db.auth
            .clone()
            .issue(revoking_refresh.account_id.clone(), identifier, issued_at).await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!("A nanoid collision was found.");
            return base::response::error(
                StatusCode::CONFLICT,
                "Thank you for being this rare.",
                None
            );
        }
        Err(_) => {
            tracing::error!(
                "Can't push a new token into database for {}",
                revoking_refresh.account_id
            );
            return base::response::internal_error(None);
        }
    }

    match state.app.db.auth.revoke(&revoking_refresh).await {
        Ok(true) => {}
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

    let token_cookie = cookies::construct("token", signed_token, "/", *TOKEN_MAX_AGE);
    let refresh_cookie = cookies::construct(
        "refresh",
        signed_refresh,
        "/account/refresh",
        *REFRESH_MAX_AGE
    );

    base::response::success(
        StatusCode::OK,
        Some(AppendHeaders(vec![(SET_COOKIE, token_cookie), (SET_COOKIE, refresh_cookie)]))
    )
}
