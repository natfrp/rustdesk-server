use std::time::Duration;

use hbb_common::ResultType;
use http::header;
use reqwest::Client;

lazy_static::lazy_static! {
    static ref API_CLIENT: Client = Client::builder()
    .timeout(Duration::from_secs(5))
    .user_agent(&std::env::var("NATFRP_UA").unwrap())
    .default_headers({
        let mut headers = header::HeaderMap::new();
        let mut auth_value =
            header::HeaderValue::from_str(&std::env::var("NATFRP_AUTH").unwrap())
                .unwrap();
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value);

        headers
    })
    .build()
    .unwrap();
}

async fn request(endpoint: &str, body: String) -> ResultType<String> {
    Ok(API_CLIENT
        .post(format!(
            "https://natfrp-api.globalslb.net/rustdesk{}",
            endpoint
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?
        .text()
        .await?)
}

#[allow(dead_code)]
pub async fn punch_hole(id: &str, token: &str) -> ResultType<String> {
    request("/punch_hole", format!("id={}&token={}", id, token)).await
}

#[allow(dead_code)]
pub async fn relay_init(id: &str, uuid: &str, token: &str, server: &str) -> ResultType<String> {
    request(
        "/relay_init",
        format!("id={}&uuid={}&token={}&server={}", id, uuid, token, server),
    )
    .await
}

#[allow(dead_code)]
pub async fn relay_open(uuid: &str) -> ResultType<String> {
    request("/relay_open", format!("uuid={}", uuid)).await
}

#[allow(dead_code)]
pub async fn change_id(old_id: &str, id: &str) -> ResultType<String> {
    request("/change_id", format!("old_id={}&id={}", old_id, id)).await
}
