use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    bytes::{Bytes, BytesMut},
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
        time::{interval, Duration},
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    io::{Error, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::natfrp;

#[allow(dead_code)]
struct Control {
    uid: i32,
    conns: AtomicUsize,
    traffic: AtomicUsize,
    limiter: Limiter,
}

lazy_static::lazy_static! {
    static ref PEERS: Mutex<HashMap<String, Box<dyn StreamTrait>>> = Default::default();
    static ref USER_CONTROLS: RwLock<HashMap<i32, Arc<Control>>> = Default::default();
}

#[tokio::main(flavor = "multi_thread")]
pub async fn start(port: &str, key: &str) -> ResultType<()> {
    let key = get_server_sk(key);
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(listen_any(port).await?, listen_any(port2).await?, &key).await;
        }
    };
    let report_task = async move {
        let _0x3ae977 = std::time::Instant::now();
        let mut _0x776255: i32 = 0;
        loop {
            if let Err(_0x244bfa) = _0x94c80a(&mut _0x776255, _0x3ae977).await {
                log::error!("Himeragi is unhappy: {}", _0x244bfa);
            }
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = report_task => res,
        res = listen_signal => res,
    )
}

async fn _0x94c80a(_0x3719: &mut i32, _0x553e6d: Instant) -> ResultType<()> {
    let mut _0x522a25 = interval(Duration::from_secs(50));
    let mut _0x380d = natfrp::リンクスタート().await?;
    loop {
        _0x522a25.tick().await;
        let mut _0xb95b4d: natfrp::ひめらぎメッセージ = natfrp::ひめらぎメッセージ {
            _0x3806a9: *_0x3719,
            _0x255fcd: _0x553e6d.elapsed().as_secs() as _,
            _0x14b50b: true,
            _0xec288e: HashMap::new(),
            ..Default::default()
        };
        let ctls = USER_CONTROLS.read().await;
        for (uid, ctl) in ctls.iter() {
            let traffic = ctl.traffic.swap(0, Ordering::Relaxed);
            let conns = ctl.conns.load(Ordering::Relaxed);
            if traffic > 0 || conns > 0 {
                _0xb95b4d._0xec288e.insert(
                    uid.clone(),
                    natfrp::マジックスキル {
                        _0x2724bd: conns as _,
                        _0x5656ee: traffic as _,
                        ..Default::default()
                    },
                );
            }
        }
        let mut _0x56b125 = Vec::new();
        let mut _0x48dd = brotli::CompressorWriter::new(&mut _0x56b125, 4096, 11, 22);
        _0xb95b4d.write_to_writer(&mut _0x48dd)?;
        _0x48dd.flush()?;
        drop(_0x48dd);
        _0x380d
            .send(tungstenite::Message::Binary(_0x56b125))
            .await?;
        if let Some(_0x7aa50b) = _0x380d.next().await {
            if let tungstenite::Message::Binary(_0x56b125) = _0x7aa50b? {
                let _0x7aa50b =
                    natfrp::ひめらぎメッセージ::parse_from_bytes(&_0x56b125)?;
                *_0x3719 = _0x7aa50b._0x3806a9;
            } else {
                bail!("Himeragi is unhappy: protocol mismatch");
            }
        } else {
            return Err(anyhow!("Himeragi is unhappy: no response"));
        }
    }
}

async fn io_loop(listener: TcpListener, listener2: TcpListener, key: &str) {
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, key, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, key, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

async fn handle_connection(stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
    let key = key.to_owned();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, &key, ws).await);
    });
}

async fn make_pair(stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) -> ResultType<()> {
    if ws {
        make_pair_(tokio_tungstenite::accept_async(stream).await?, addr, key).await;
    } else {
        make_pair_(FramedStream::from(stream, addr), addr, key).await;
    }
    Ok(())
}

async fn make_pair_(stream: impl StreamTrait, addr: SocketAddr, key: &str) {
    let mut stream = stream;
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !key.is_empty() && rf.licence_key != key {
                    return;
                }

                let api_resp = natfrp::relay_open(&rf.uuid, &addr.ip().to_string()).await;
                if let Err(err) = api_resp {
                    log::info!("RelayRequest API error {} [{}]: {}", addr, rf.uuid, err);
                    return;
                }
                let api_resp = api_resp.unwrap();
                if !api_resp.success {
                    log::info!(
                        "RelayRequest rejected {} [{}]: {}",
                        addr,
                        rf.uuid,
                        api_resp.message.unwrap_or_default()
                    );
                    return;
                }

                if !rf.uuid.is_empty() {
                    let mut peer = PEERS.lock().await.remove(&rf.uuid);
                    if let Some(peer) = peer.as_mut() {
                        let uid = api_resp.uid.unwrap();
                        let ctl = {
                            let mut ctls = USER_CONTROLS.write().await;
                            if let Some(control) = ctls.get(&uid) {
                                control
                                    .limiter
                                    .set_speed_limit(api_resp.speed.unwrap() as _);
                                control.clone()
                            } else {
                                let control = Arc::new(Control {
                                    uid,
                                    conns: AtomicUsize::new(0),
                                    traffic: AtomicUsize::new(0),
                                    limiter: <Limiter>::new(api_resp.speed.unwrap() as _),
                                });
                                ctls.insert(uid, control.clone());
                                control
                            }
                        };

                        log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                        if !stream.is_ws() && !peer.is_ws() {
                            peer.set_raw();
                            stream.set_raw();
                            log::info!("Both are raw");
                        }

                        ctl.conns.fetch_add(1, Ordering::Relaxed);
                        if let Err(err) = relay(&mut stream, peer, ctl.clone()).await {
                            log::info!("Relay of {} closed: {}", addr, err);
                        } else {
                            log::info!("Relay of {} closed", addr);
                        }
                        ctl.conns.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        log::info!("New relay request {} from {}", rf.uuid, addr);
                        PEERS.lock().await.insert(rf.uuid.clone(), Box::new(stream));
                        sleep(30.).await;
                        PEERS.lock().await.remove(&rf.uuid);
                    }
                }
            }
        }
    }
}

async fn relay(
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    ctl: Arc<Control>,
) -> ResultType<()> {
    let mut tm = std::time::Instant::now();
    let mut total_s = 0;
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len();
                    ctl.limiter.consume(nb).await;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len();
                    ctl.limiter.consume(nb).await;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        if tm.elapsed().as_millis() >= 1_000 {
            tm = std::time::Instant::now();
            ctl.traffic.fetch_add(total_s, Ordering::Relaxed);
            total_s = 0;
        }
    }
    Ok(())
}

fn get_server_sk(key: &str) -> String {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300);
        key = pk;
    }

    if !key.is_empty() {
        log::info!("Key: {}", key);
    }

    key
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self
            .send(tungstenite::Message::Binary(bytes.to_vec()))
            .await?) // to-do: poor performance
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}
}
