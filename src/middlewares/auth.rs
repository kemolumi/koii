use std::sync::Arc;

use axum::{
    extract::{ Request, State },
    http::HeaderMap,
    middleware::Next,
    response::IntoResponse,
};
use cookie_rs::CookieJar;
use reqwest::header::COOKIE;

use crate::{
    AppState,
    base,
    database::auth::AuthOperationError,
    utils::jwt::{ KeyClaims, KeyKind },
};

#[derive(Clone)]
pub struct AuthorizationInfo {
    /// This value satisfies when `token` or `refresh` is valid.
    pub active: bool,
    pub token: Option<KeyClaims>,
    pub refresh: Option<KeyClaims>,
}

pub async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next
) -> impl IntoResponse {
    let failed = AuthorizationInfo {
        active: false,
        token: None,
        refresh: None,
    };

    let cookies = match headers.get(COOKIE) {
        Some(cookies) => cookies,
        None => {
            request.extensions_mut().insert(failed);
            return next.run(request).await;
        }
    };
    let cookies = match cookies.to_str() {
        Ok(cookies) => cookies,
        Err(_) => {
            request.extensions_mut().insert(failed);
            return next.run(request).await;
        }
    };

    match parse_cookies(state, cookies).await {
        Ok(info) => {
            request.extensions_mut().insert(info);
        }
        Err(_) => {
            return base::response::internal_error::<u8>(None).into_response();
        }
    }

    next.run(request).await
}

async fn parse_cookies(
    state: Arc<AppState>,
    cookies: &str
) -> Result<AuthorizationInfo, AuthOperationError> {
    let mut token = None;
    let mut refresh = None;
    let mut active = false;

    let Ok(jar) = CookieJar::parse(cookies) else {
        return Ok(AuthorizationInfo {
            active: false,
            token: None,
            refresh: None,
        });
    };

    if
        let Some(payload) = jar.get("token") &&
        let Some(claims) = state.jwt.verify(payload.value(), KeyKind::Authentication)
    {
        match state.db.auth.check_token(&claims).await {
            Ok(true) => {
                token = Some(claims);
                active = true;
            }
            Ok(false) => {} // The token is revoked, don't add anything.
            Err(error) => {
                tracing::error!(
                    "Failed to query database for token `{}`: {error}",
                    payload.value()
                );
            }
        }
    }

    if
        let Some(payload) = jar.get("refresh") &&
        let Some(claims) = state.jwt.verify(payload.value(), KeyKind::Refresh)
    {
        match state.db.auth.check_token(&claims).await {
            Ok(true) => {
                refresh = Some(claims);
                active = true;
            }
            Ok(false) => {} // The refresh is revoked, don't add anything.
            Err(error) => {
                tracing::error!(
                    "Failed to query database for refresh `{}`: {error}",
                    payload.value()
                );
            }
        }
    }

    Ok(AuthorizationInfo {
        active,
        token,
        refresh,
    })
}
