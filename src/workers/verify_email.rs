use std::{ collections::HashMap, thread };
use resend_rs::{ Resend, types::{ CreateEmailBaseOptions, EmailTemplate } };
use tokio::sync::oneshot;

use crate::{
    env::{ EMAIL_BATCHING_WINDOW, ORIGIN_DOMAIN, RESEND_TOKEN },
    types::{ EmailAddress, VerifyCode },
};

pub struct VerifyEmailRequest {
    pub email: EmailAddress,
    pub verify_code: VerifyCode,
}

// The oneshot param is required by design for each services, but we don't use it.
pub fn launch(
    rx: kanal::AsyncReceiver<(VerifyEmailRequest, Option<oneshot::Sender<()>>)>,
    threads: usize
) {
    if threads > 1 {
        tracing::warn!("But sire, there can only be 1 email worker.");
    }

    let rx = rx.to_sync();
    thread::spawn(|| { worker(rx) });
}

fn worker(rx: kanal::Receiver<(VerifyEmailRequest, Option<oneshot::Sender<()>>)>) {
    // DO NOT MOVE THIS UP TO THE LAUNCHER FUNCTION.
    // Resend uses `reqwest` under the hood.
    // And if it's defined as blocking, it can't be initialized inside of tokio context.
    let resend = Resend::new(&RESEND_TOKEN);

    let mut requests = Vec::with_capacity(100);

    loop {
        let waiting = rx.len();
        if waiting > 1 {
            rx.drain_into(&mut requests).unwrap();

            let batch: Vec<CreateEmailBaseOptions> = requests
                .iter()
                .map(|request| { create_verify_base(&request.0) })
                .collect();

            if let Err(error) = resend.batch.send(batch) {
                tracing::error!("Can't send email batch to Resend API: {error}");
            }

            continue;
        }

        if waiting == 1 {
            let request = rx.recv().unwrap();
            if let Err(error) = resend.emails.send(create_verify_base(&request.0)) {
                tracing::error!("Can't send email batch to Resend API: {error}");
            }
        }

        thread::sleep(*EMAIL_BATCHING_WINDOW);
    }
}

fn create_verify_base(request: &VerifyEmailRequest) -> CreateEmailBaseOptions {
    let mut variables = HashMap::new();
    variables.insert(
        "VERIFY_LINK".to_string(),
        serde_json::Value::String(
            format!(
                "https://{}/verify?code={}",
                ORIGIN_DOMAIN.domain().unwrap(),
                request.verify_code
            )
        )
    );

    CreateEmailBaseOptions::new(
        format!("Koii Auth <auth@{}>", ORIGIN_DOMAIN.domain().unwrap()),
        [request.email.as_str()],
        "Koii email verification"
    ).with_template(EmailTemplate::new("koii-verify").with_variables(variables))
}
