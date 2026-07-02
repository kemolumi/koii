use axum::{ http::{ HeaderName, StatusCode }, response::AppendHeaders };
use nanoid::nanoid;
use reqwest::header::SET_COOKIE;

use crate::{
    base::{ self, response::ResponseModel },
    database::auth::AuthOperations,
    env::{ ACCOUNT_TOKEN_IDENTIFIER_LENGTH, REFRESH_MAX_AGE, TOKEN_MAX_AGE },
    utils::jwt::{ JwtService, KeyClaims, KeyKind },
};

/// Handles `issued_at` and `identifier` automatically.
///
/// The function will call `AuthOperations` to store the issued token too.
///
/// Any problems happens while issuing will return a response, so handler can return the error to client.
pub async fn quick_issue<R>(
    auth: &AuthOperations,
    jwt: &JwtService,
    account_id: String
) -> Result<AppendHeaders<Vec<(HeaderName, String)>>, ResponseModel<R>> {
    let identifier = nanoid!(*ACCOUNT_TOKEN_IDENTIFIER_LENGTH);
    let issued_at = base::timestamp::now();

    let signed_token = jwt.generate(KeyClaims {
        account_id: account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Authentication,
        iat: issued_at,
        exp: issued_at + *TOKEN_MAX_AGE,
    });

    let signed_refresh = jwt.generate(KeyClaims {
        account_id: account_id.clone(),
        identifier: identifier.clone(),
        kind: KeyKind::Refresh,
        iat: issued_at,
        exp: issued_at + *REFRESH_MAX_AGE,
    });

    match auth.issue(account_id, identifier, issued_at).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!("A nanoid collision was found.");
            return Err(
                base::response::error(StatusCode::CONFLICT, "Thank you for being this rare.", None)
            );
        }
        Err(error) => {
            tracing::error!("Unable to issue a token ({signed_token}): {error}");
            return Err(base::response::internal_error(None));
        }
    }

    let token_cookie = base::cookies::construct("token", signed_token, "/", *TOKEN_MAX_AGE);
    let refresh_cookie = base::cookies::construct(
        "refresh",
        signed_refresh,
        "/account/refresh",
        *REFRESH_MAX_AGE
    );

    Ok(AppendHeaders(vec![(SET_COOKIE, token_cookie), (SET_COOKIE, refresh_cookie)]))
}
