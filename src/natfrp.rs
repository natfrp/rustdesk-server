use std::{env, time::Duration};

use hbb_common::{
    bail,
    futures_util::{SinkExt, StreamExt},
    protobuf,
    tokio::net::TcpStream,
    ResultType,
};
use http::header;
use native_tls::{Certificate, TlsConnector};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use tungstenite::client::IntoClientRequest;

lazy_static::lazy_static! {
    static ref API_CLIENT: Client = Client::builder()
    .timeout(Duration::from_secs(5))
    .user_agent(env::var("NATFRP_UA").unwrap())
    .default_headers({
        let mut headers = header::HeaderMap::new();
        let mut auth_value =
            header::HeaderValue::from_str(&env::var("NATFRP_AUTH").unwrap())
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
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?
        .text()
        .await?)
}

#[allow(dead_code)]
pub async fn punch_hole(id: &str, token: &str, ip: &str, port: u16) -> ResultType<String> {
    request(
        "/punch_hole",
        format!("id={}&token={}&ip={}&port={}", id, token, ip, port),
    )
    .await
}

#[allow(dead_code)]
pub async fn relay_init(
    id: &str,
    uuid: &str,
    token: &str,
    server: &str,
    ip: &str,
    port: u16,
) -> ResultType<String> {
    request(
        "/relay_init",
        format!(
            "id={}&uuid={}&token={}&server={}&ip={}&port={}",
            id, uuid, token, server, ip, port
        ),
    )
    .await
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RelayOpenResponse {
    pub success: bool,
    pub message: Option<String>,
    pub speed: Option<u32>,
    pub uid: Option<i32>,
}

#[allow(dead_code)]
pub async fn relay_open(uuid: &str, ip: &str, port: u16) -> ResultType<RelayOpenResponse> {
    Ok(serde_json::from_str(
        &request(
            "/relay_open",
            format!("uuid={}&ip={}&port={}", uuid, ip, port),
        )
        .await?,
    )?)
}

#[allow(dead_code)]
pub async fn change_id(old_id: &str, id: &str, ip: &str, port: u16) -> ResultType<String> {
    request(
        "/change_id",
        format!("old_id={}&id={}&ip={}&port={}", old_id, id, ip, port),
    )
    .await
}

#[allow(dead_code)]
pub async fn リンクスタート() -> ResultType<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut _0x2df839 = env::var("HIMERAGI_MAGIC")
        .unwrap()
        .into_client_request()
        .unwrap();
    _0x2df839.headers_mut().insert(
        header::USER_AGENT,
        header::HeaderValue::from_str("NATFRP_UA").unwrap(),
    );
    let mut _0x5e781c = tokio_tungstenite::client_async_tls_with_config(
        _0x2df839,
        TcpStream::connect(env::var("HIMERAGI_MAGIA").unwrap()).await?,
        None,
        Some(Connector::NativeTls(
            TlsConnector::builder()
                .disable_built_in_roots(true)
                .add_root_certificate(
                    Certificate::from_pem(
                        &std::fs::read(env::var("HIMERAGI_MAGIKA").unwrap()).unwrap(),
                    )
                    .unwrap(),
                )
                .danger_accept_invalid_hostnames(true)
                .build()
                .unwrap(),
        )),
    )
    .await?
    .0;
    _0x5e781c
        .send(tokio_tungstenite::tungstenite::Message::Text(
            env::var("HIMERAGI_MAGIK").unwrap(),
        ))
        .await?;
    let _0x38d559 = _0x5e781c.next().await;
    if _0x38d559.is_none() {
        bail!("jesus christ");
    }
    let _0x38d559 = _0x38d559.unwrap()?;
    if _0x38d559.into_text()? != env::var("HIMERAGI_MAGIX").unwrap() {
        bail!("too bad");
    }
    Ok(_0x5e781c)
}

#[derive(PartialEq, Clone, Default, Debug)]
pub struct マジックスキル {
    pub _0x2724bd: i32,
    pub _0x5656ee: i64,
    pub _0x15ad9d: protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a マジックスキル {
    fn default() -> &'a マジックスキル {
        <マジックスキル as protobuf::Message>::default_instance()
    }
}

impl protobuf::Message for マジックスキル {
    const NAME: &'static str = "_0x778488"; // useless, just to satisfy the impl

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, _: &mut protobuf::CodedInputStream<'_>) -> protobuf::Result<()> {
        panic!("_0xf894")
    }

    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut _0x2758a7 = 0;
        if self._0x2724bd != 0 {
            _0x2758a7 += protobuf::rt::int32_size(1, self._0x2724bd);
        }
        if self._0x5656ee != 0 {
            _0x2758a7 += protobuf::rt::int64_size(2, self._0x5656ee);
        }
        _0x2758a7 += protobuf::rt::unknown_fields_size(self._0x15ad9d.unknown_fields());
        self._0x15ad9d.cached_size().set(_0x2758a7 as u32);
        _0x2758a7
    }

    fn write_to_with_cached_sizes(
        &self,
        _0xb9c3a7: &mut protobuf::CodedOutputStream<'_>,
    ) -> protobuf::Result<()> {
        if self._0x2724bd != 0 {
            _0xb9c3a7.write_int32(1, self._0x2724bd)?;
        }
        if self._0x5656ee != 0 {
            _0xb9c3a7.write_int64(2, self._0x5656ee)?;
        }
        _0xb9c3a7.write_unknown_fields(self._0x15ad9d.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &protobuf::SpecialFields {
        &self._0x15ad9d
    }

    fn mut_special_fields(&mut self) -> &mut protobuf::SpecialFields {
        &mut self._0x15ad9d
    }

    fn new() -> マジックスキル {
        Default::default()
    }

    fn clear(&mut self) {
        self._0x2724bd = 0;
        self._0x5656ee = 0;
        self._0x15ad9d.clear();
    }

    fn default_instance() -> &'static マジックスキル {
        static _0X3E9888: マジックスキル = マジックスキル {
            _0x2724bd: 0,
            _0x5656ee: 0,
            _0x15ad9d: protobuf::SpecialFields::new(),
        };
        &_0X3E9888
    }
}

#[derive(PartialEq, Clone, Default, Debug)]
pub struct ひめらぎメッセージ {
    pub _0x3806a9: i32,
    pub _0x255fcd: i32,
    pub _0x14b50b: bool,
    pub _0xec288e: ::std::collections::HashMap<i32, マジックスキル>,
    pub _0x56d576: protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ひめらぎメッセージ {
    fn default() -> &'a ひめらぎメッセージ {
        <ひめらぎメッセージ as protobuf::Message>::default_instance()
    }
}

impl protobuf::Message for ひめらぎメッセージ {
    const NAME: &'static str = "_0x5063d4"; // useless, just to satisfy the impl

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(
        &mut self,
        _0x17ceac: &mut protobuf::CodedInputStream<'_>,
    ) -> protobuf::Result<()> {
        while let Some(_0x21d77d) = _0x17ceac.read_raw_tag_or_eof()? {
            match _0x21d77d {
                8 => {
                    self._0x3806a9 = _0x17ceac.read_int32()?;
                }
                _0x3d184b => {
                    panic!("_0x50d843")
                }
            };
        }
        ::std::result::Result::Ok(())
    }

    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut _0x4ae4 = 0;
        if self._0x3806a9 != 0 {
            _0x4ae4 += protobuf::rt::int32_size(1, self._0x3806a9);
        }
        if self._0x255fcd != 0 {
            _0x4ae4 += protobuf::rt::int32_size(6, self._0x255fcd);
        }
        if self._0x14b50b != false {
            _0x4ae4 += 1 + 1;
        }
        for (k, v) in &self._0xec288e {
            let mut _0x4d8739 = 0;
            _0x4d8739 += protobuf::rt::int32_size(1, *k);
            let len = v.compute_size();
            _0x4d8739 += 1 + protobuf::rt::compute_raw_varint64_size(len) + len;
            _0x4ae4 += 1 + protobuf::rt::compute_raw_varint64_size(_0x4d8739) + _0x4d8739
        }
        _0x4ae4 += protobuf::rt::unknown_fields_size(self._0x56d576.unknown_fields());
        self._0x56d576.cached_size().set(_0x4ae4 as u32);
        _0x4ae4
    }

    fn write_to_with_cached_sizes(
        &self,
        _0xc7a24b: &mut protobuf::CodedOutputStream<'_>,
    ) -> protobuf::Result<()> {
        if self._0x3806a9 != 0 {
            _0xc7a24b.write_int32(1, self._0x3806a9)?;
        }
        if self._0x255fcd != 0 {
            _0xc7a24b.write_int32(6, self._0x255fcd)?;
        }
        if self._0x14b50b != false {
            _0xc7a24b.write_bool(9, self._0x14b50b)?;
        }
        for (k, v) in &self._0xec288e {
            let mut _0x48e28e = 0;
            _0x48e28e += protobuf::rt::int32_size(1, *k);
            let _0x425863 = v.cached_size() as u64;
            _0x48e28e += 1 + protobuf::rt::compute_raw_varint64_size(_0x425863) + _0x425863;
            _0xc7a24b.write_raw_varint32(82)?; // hmm, tag.
            _0xc7a24b.write_raw_varint32(_0x48e28e as u32)?;
            _0xc7a24b.write_int32(1, *k)?;
            protobuf::rt::write_message_field_with_cached_size(2, v, _0xc7a24b)?;
        }
        _0xc7a24b.write_unknown_fields(self._0x56d576.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &protobuf::SpecialFields {
        &self._0x56d576
    }

    fn mut_special_fields(&mut self) -> &mut protobuf::SpecialFields {
        &mut self._0x56d576
    }

    fn new() -> ひめらぎメッセージ {
        Default::default()
    }

    fn clear(&mut self) {
        self._0x3806a9 = 0;
        self._0x255fcd = 0;
        self._0x14b50b = false;
        self._0xec288e.clear();
        self._0x56d576.clear();
    }

    fn default_instance() -> &'static ひめらぎメッセージ {
        static _0X3CBD: protobuf::rt::Lazy<ひめらぎメッセージ> = protobuf::rt::Lazy::new();
        _0X3CBD.get(ひめらぎメッセージ::new)
    }
}
