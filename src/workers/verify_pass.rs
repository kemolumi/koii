use std::thread;

use argon2::{ Argon2, PasswordHash, PasswordVerifier };
use tokio::sync::oneshot;

use crate::{
    env::{ ARGON2_MEMORY_COST, ARGON2_OUTPUT_LENGTH, ARGON2_PARALLELISM_COST, ARGON2_TIME_COST },
    types::{ HashedPassword, RawPassword },
};

pub struct VerifyPassRequest {
    pub password: RawPassword,
    pub hash: HashedPassword,
}

pub fn launch(
    rx: kanal::AsyncReceiver<
        (VerifyPassRequest, Option<oneshot::Sender<Result<bool, argon2::password_hash::Error>>>)
    >,
    threads: usize
) {
    let argon2id = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::ParamsBuilder
            ::new()
            .m_cost(*ARGON2_MEMORY_COST)
            .p_cost(*ARGON2_PARALLELISM_COST)
            .t_cost(*ARGON2_TIME_COST)
            .output_len(*ARGON2_OUTPUT_LENGTH)
            .build()
            .unwrap()
    );

    for _ in 0..threads {
        let rx_branch = rx.clone().to_sync();
        let argon2id_branch = argon2id.clone();
        thread::spawn(|| { worker(rx_branch, argon2id_branch) });
    }
}

fn worker(
    rx: kanal::Receiver<
        (VerifyPassRequest, Option<oneshot::Sender<Result<bool, argon2::password_hash::Error>>>)
    >,
    argon2id: Argon2
) {
    while let Ok((request, Some(sender))) = rx.recv() {
        match PasswordHash::new(request.hash.as_str()) {
            Ok(hash) => {
                let _ = sender.send(
                    Ok(argon2id.verify_password(request.password.as_bytes(), &hash).is_ok())
                );
            }
            Err(error) => {
                let _ = sender.send(Err(error));
            }
        }
    }
}
