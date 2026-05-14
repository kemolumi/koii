use reqwest::StatusCode;

use crate::base::{ self, response::ResponseModel };

pub async fn handler() -> ResponseModel {
    base::response::result(StatusCode::CREATED, "I love you too.".into(), None)
}
