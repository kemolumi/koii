use axum::{ Extension, extract::State };
use reqwest::StatusCode;

use crate::{
    base::{ self, response::ResponseModel },
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

    let headers = match
        base::auth::quick_issue(
            &state.app.db.auth,
            &state.app.jwt,
            revoking_refresh.account_id.clone()
        ).await
    {
        Ok(headers) => headers,
        Err(bad) => {
            return bad;
        }
    };

    match state.app.db.auth.revoke(&revoking_refresh).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("Failed to revoke a token.");
            return base::response::internal_error(None);
        }
        Err(_) => {
            return base::response::internal_error(None);
        }
    }

    base::response::success(StatusCode::OK, Some(headers))
}
