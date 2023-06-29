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

#[allow(dead_code)]
pub async fn auth(token: String) -> ResultType<String> {
    Ok(API_CLIENT
        .post("https://natfrp-api.globalslb.net/rustdesk/auth")
        .body(token)
        .send()
        .await?
        .text()
        .await?)
}

#[allow(dead_code)]
pub async fn relay_init(uuid: String, token: String) -> ResultType<String> {
    Ok(API_CLIENT
        .post("https://natfrp-api.globalslb.net/rustdesk/relay_init")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("uuid={}&token={}", uuid, token))
        .send()
        .await?
        .text()
        .await?)
}

#[allow(dead_code)]
pub async fn relay_open(uuid: String) -> ResultType<bool> {
    Ok(API_CLIENT
        .post("https://natfrp-api.globalslb.net/rustdesk/relay_open")
        .body(uuid)
        .send()
        .await?
        .text()
        .await?
        == "OK")
}
