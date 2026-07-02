use std::{ sync::Arc, time::Duration };

use axum::{ Router, routing::{ get, patch, post } };

use crate::{ AppState, middlewares::{ auth, time } };

mod create;
mod verify;
mod login;
mod totp;
mod logout;
mod delete;
pub mod refresh;

#[derive(Clone)]
pub struct AccountRoutesState {
    pub app: Arc<AppState>,
}

pub fn routes(app_state: Arc<AppState>) -> Router {
    let state = AccountRoutesState {
        app: app_state,
    };

    Router::new()
        .route("/", post(create::handler).delete(delete::handler))
        .route("/verify", patch(verify::handler))
        .route("/login", post(login::handler))
        .route("/refresh", get(refresh::handler))
        .nest("/totp", totp::routes(state.clone()))
        .route("/logout", get(logout::handler))
        .layer(axum::middleware::from_fn_with_state(state.app.clone(), auth::authorize))
        .layer(axum::middleware::from_fn_with_state(Duration::from_millis(800), time::padding))
        .with_state(state)
}
