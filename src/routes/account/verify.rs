use axum::{ Extension, Json, extract::State, http::StatusCode };
use serde::Deserialize;

use crate::{
    base::{ self, response::ResponseModel },
    middlewares::auth::AuthorizationInfo,
    routes::account::AccountRoutesState,
};

#[derive(Deserialize)]
pub struct VerifyPayload {
    pub verify_code: String,
}

pub async fn handler(
    Extension(authorization_info): Extension<AuthorizationInfo>,
    State(state): State<AccountRoutesState>,
    Json(payload): Json<VerifyPayload>
) -> ResponseModel {
    if authorization_info.active {
        return base::response::error(
            StatusCode::FORBIDDEN,
            "There's already an active account.",
            None
        );
    }

    match state.app.db.account.verify_email(&payload.verify_code.into()).await {
        Ok(true) => {}
        Ok(false) => {
            return base::response::error(
                StatusCode::NOT_FOUND,
                "There's no account associated to this verify token.",
                None
            );
        }
        Err(error) => {
            tracing::error!("Database failed to verify account: {}", error);
            return base::response::internal_error(None);
        }
    }

    base::response::success(StatusCode::OK, None)
}
