use std::time::Duration;

pub fn now() -> Duration {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap()
}
