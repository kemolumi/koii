use axum::Router;
use axum::routing::post;

use crate::{ routes::account::AccountRoutesState };

mod create;
mod delete;
mod login;

pub fn routes(state: AccountRoutesState) -> Router<AccountRoutesState> {
    Router::new()
        .route("/", post(create::handler).delete(delete::handler))
        .route("/login", post(login::handler))
        .with_state(state)
}
