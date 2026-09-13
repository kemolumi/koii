use std::thread;

use argon2::{ Argon2, password_hash::{ PasswordHasher, SaltString, rand_core::OsRng } };
use tokio::sync::{ oneshot };

use crate::{
    env::{ ARGON2_MEMORY_COST, ARGON2_OUTPUT_LENGTH, ARGON2_PARALLELISM_COST, ARGON2_TIME_COST },
    types::{ HashedPassword, RawPassword },
};

pub fn launch(
    rx: kanal::AsyncReceiver<
        (RawPassword, Option<oneshot::Sender<Result<HashedPassword, argon2::password_hash::Error>>>)
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
        (RawPassword, Option<oneshot::Sender<Result<HashedPassword, argon2::password_hash::Error>>>)
    >,
    argon2id: Argon2
) {
    while let Ok((password, Some(sender))) = rx.recv() {
        let salt = SaltString::generate(&mut OsRng);
        match argon2id.hash_password(password.as_bytes(), &salt) {
            Ok(hashed) => {
                let _ = sender.send(Ok(hashed.to_string().into()));
            }
            Err(error) => {
                let _ = sender.send(Err(error));
            }
        }
    }
}
