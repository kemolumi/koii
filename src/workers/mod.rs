use tokio::sync::oneshot;

use crate::workers::{ verify_email::VerifyEmailRequest, verify_pass::VerifyPassRequest };

pub mod hash_pass;
pub mod verify_pass;
pub mod verify_email;

pub struct WorkerSpec {
    pub threads: usize,
    pub buffer: usize,
}

// Tuple (thread amount, channel's buffer)
pub struct WorkersAllocate {
    pub hash_pass: WorkerSpec,
    pub verify_pass: WorkerSpec,
    pub verify_email: WorkerSpec,
}

pub struct Workers {
    pub hash_pass: RequestHandler<String, Option<String>>,
    pub verify_pass: RequestHandler<VerifyPassRequest, Option<bool>>,
    pub verify_email: RequestHandler<VerifyEmailRequest, Option<()>>,
}
impl Workers {
    pub fn new(allocate: WorkersAllocate) -> Self {
        tracing::info!("Spawning workers...");

        Workers {
            hash_pass: RequestHandler::new(
                hash_pass::launch,
                allocate.hash_pass.threads,
                allocate.hash_pass.buffer
            ),
            verify_pass: RequestHandler::new(
                verify_pass::launch,
                allocate.verify_pass.threads,
                allocate.verify_pass.buffer
            ),
            verify_email: RequestHandler::new(
                verify_email::launch,
                allocate.verify_email.threads,
                allocate.verify_email.buffer
            ),
        }
    }
}

pub struct RequestHandler<R, P> {
    tx: kanal::AsyncSender<(R, Option<oneshot::Sender<P>>)>,
}
impl<R, P> RequestHandler<R, P> {
    pub fn new<F: Fn(kanal::AsyncReceiver<(R, Option<oneshot::Sender<P>>)>, usize)>(
        launcher: F,
        threads: usize,
        buffer: usize
    ) -> Self {
        let (service_tx, service_rx) = kanal::bounded_async::<(R, Option<oneshot::Sender<P>>)>(
            buffer
        );
        launcher(service_rx, threads);

        RequestHandler {
            tx: service_tx,
        }
    }

    /// Send a request to the worker and wait for `Result<P, ()>`
    pub async fn send(&self, request: R) -> Result<P, ()> {
        let (one_tx, one_rx) = oneshot::channel::<P>();

        if let Err(_) = self.tx.send((request, Some(one_tx))).await {
            return Err(());
        }

        if let Ok(result) = one_rx.await {
            return Ok(result);
        } else {
            return Err(());
        }
    }

    /// Send a request to the worker, but ignore output from the worker.
    pub async fn send_ignore(&self, request: R) -> Result<(), ()> {
        if let Err(_) = self.tx.send((request, None)).await {
            return Err(());
        }

        Ok(())
    }
}
