use std::time::Duration;

use axum::{ Router, middleware };
use axum::routing::{ get, post };

use crate::middlewares::time;
use crate::{ routes::account::AccountRoutesState };

mod methods;
mod request;
mod elevate;

pub fn routes(state: AccountRoutesState) -> Router<AccountRoutesState> {
    Router::new()
        .route("/methods", get(methods::handler))
        .route("/elevate", post(elevate::handler))
        .layer(middleware::from_fn_with_state(Duration::from_secs(2), time::padding))
        .with_state(state)
}
