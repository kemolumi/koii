use std::time::Duration;

use cookie_rs::{ Cookie, cookie::SameSite };

use crate::env::ORIGIN_DOMAIN;

pub fn construct(name: &str, value: String, path: &str, max_age: Duration) -> String {
    Cookie::builder(name, value)
        .domain(format!(".{}", ORIGIN_DOMAIN.domain().unwrap()))
        .path(path)
        .max_age(max_age)
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true)
        .build()
        .to_string()
}

pub fn remove(name: &str, path: &str) -> String {
    Cookie::builder(name, "X")
        .domain(format!(".{}", ORIGIN_DOMAIN.domain().unwrap()))
        .path(path)
        .max_age(Duration::from_secs(0))
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true)
        .build()
        .to_string()
}
