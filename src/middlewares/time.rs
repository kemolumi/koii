use std::time::Duration;
use axum::{ extract::{ Request, State }, middleware::Next, response::IntoResponse };
use tokio::time::Instant;

pub async fn padding(
    State(pad): State<Duration>,
    request: Request,
    next: Next
) -> impl IntoResponse {
    let start = Instant::now();
    let response = next.run(request).await;

    let finish = start.elapsed();

    tracing::debug!(
        "Request finished in {}ms, raising to {}ms",
        finish.as_millis(),
        pad.as_millis()
    );

    if finish < pad {
        tokio::time::sleep(pad - finish).await;
    } else {
        tracing::warn!(
            "Time spent was too much for raising: {}ms > {}ms",
            finish.as_millis(),
            pad.as_millis()
        );
    }

    response
}
