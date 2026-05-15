use std::time::Duration;

use serde::Deserialize;

use crate::env::TURNSTILE_SECRET;

#[derive(Deserialize)]
pub struct TurnstileResult {
    pub success: bool,
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Option<Vec<String>>,
    pub action: Option<String>,
    pub cdata: Option<String>,
    pub messages: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

pub struct Turnstile {
    http_client: reqwest::Client,
    retries: usize,
}
impl Turnstile {
    pub fn default() -> Self {
        Turnstile {
            http_client: reqwest::Client
                ::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            retries: 3,
        }
    }

    /// More strict checks needed.
    pub async fn verify(&self, clientstile: String, bypass: bool) -> Result<bool, ()> {
        if bypass {
            tracing::warn!("Bypass method for Turnstile was called.");
            return Ok(true);
        }
        if clientstile.len() > 2048 {
            return Ok(false);
        }

        let request_construct = self.http_client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(
                &[
                    ("secret", &*TURNSTILE_SECRET),
                    ("response", &clientstile),
                ]
            );

        let mut tries = 0;
        let response = loop {
            let request_instance = match request_construct.try_clone() {
                Some(instance) => instance,
                None => {
                    tracing::error!("Bad request construct");
                    break None;
                }
            };
            match request_instance.send().await {
                Ok(response) => {
                    match response.json::<TurnstileResult>().await {
                        Ok(response) => {
                            break Some(response);
                        }
                        Err(error) => {
                            tracing::error!("{error}");
                        }
                    }
                }
                Err(error) => {
                    tracing::error!("{error}");
                }
            }

            tries += 1;
            if tries >= self.retries {
                break None;
            }
        };

        return match response {
            Some(response) => Ok(response.success),
            None => Err(()),
        };
    }
}
