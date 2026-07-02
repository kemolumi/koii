mod register;
mod delete;
mod complete;

use axum::{ Router, routing::{ patch, post } };

use crate::{ routes::account::AccountRoutesState };

pub fn routes(state: AccountRoutesState) -> Router<AccountRoutesState> {
    Router::new()
        .route("/", post(register::handler).delete(delete::handler))
        .route("/complete", patch(handler))
        .with_state(state)
}
