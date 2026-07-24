use crate::common::*;
use crate::database::{DeviceAdmissionFailure, DeviceAdmissionResult};
use crate::license::{self, LicenseError};
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::*,
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration, MissedTickBehavior},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i32 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationResult {
    Ok,
    UuidMismatch,
    TooFrequent,
    LicenseMismatch,
    LicenseOveruse { current: u32, max: u32 },
    ServerError,
}
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    TcpStream(TcpStreamSink),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry {
    tm: Instant,
    from_ip: String,
    to_ip: String,
    to_id: String,
}
static PUNCH_REQS: Lazy<TokioMutex<Vec<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(Vec::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
    pro_enabled: bool,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
    pending_registrations: Arc<Mutex<PendingRegistrationLimiter>>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
}

impl RendezvousServer {
    #[tokio::main(flavor = "multi_thread")]
    pub async fn start(
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
        pro_enabled: bool,
        mut device_rx: DeviceInvalidationReceiver,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key);
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        let startup_offline = pm.db.mark_startup_online_offline().await?;
        if startup_offline > 0 {
            log::info!(
                "启动时已将 {} 个残留 online 设备校正为 offline",
                startup_offline
            );
        }
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        log::info!("Listening on tcp/udp :{}", port);
        log::info!("Listening on tcp :{}, extra port for NAT test", nat_port);
        log::info!("Listening on websocket :{}", ws_port);
        let mut socket = create_udp_listener(port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
                pro_enabled,
            }),
            pending_registrations: Arc::new(Mutex::new(PendingRegistrationLimiter::default())),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(port).await?;
        let mut listener2 = create_tcp_listener(nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_port).await?;
        let test_addr = std::env::var("TEST_HBBS").unwrap_or_default();
        if std::env::var("ALWAYS_USE_RELAY")
            .unwrap_or_default()
            .to_uppercase()
            == "Y"
        {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut socket,
                        &key,
                        &mut device_rx,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(nat_port).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    // 主事件循环显式持有各监听器与两个命令接收端，避免把运行时资源藏入全局状态。
    #[allow(clippy::too_many_arguments)]
    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        socket: &mut FramedSocket,
        key: &str,
        device_rx: &mut DeviceInvalidationReceiver,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        timer_check_relay.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut timer_offline = interval(Duration::from_secs(5));
        timer_offline.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut timer_inactive = interval(Duration::from_secs(60 * 60));
        timer_inactive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                Some(command) = device_rx.recv() => {
                    self.handle_device_invalidation_command(command).await;
                }
                _ = timer_offline.tick() => {
                    if let Err(err) = self.pm.db.mark_stale_online_offline().await {
                        log::error!("online 转 offline 后台任务失败: {:#}", err);
                    }
                }
                _ = timer_inactive.tick() => {
                    match self.pm.db.mark_stale_offline_inactive().await {
                        Ok(ids) => {
                            for id in ids {
                                if let Err(err) = self.pm.invalidate_if_still_inactive(&id).await {
                                    log::error!("后台清理设备 {} 缓存失败: {:#}", id, err);
                                }
                            }
                        }
                        Err(err) => log::error!("offline 转 inactive 后台任务失败: {:#}", err),
                    }
                }
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    async fn handle_device_invalidation_command(&self, command: DeviceInvalidationCommand) {
        let DeviceInvalidationCommand {
            device_id,
            predicate,
            ack,
        } = command;
        let result = match self.pm.invalidate(&device_id, predicate).await {
            Ok(result) => Ok(result),
            Err(err) => {
                log::error!("处理设备 {} 缓存失效命令失败: {:#}", device_id, err);
                Err(())
            }
        };
        let _ = ack.send(result);
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    let result = self.register_pk(rk, addr).await;
                    send_registration_result(socket, addr, result).await?;
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    if self.pm.is_in_memory(&ph.id).await {
                        self.handle_udp_punch_hole_request(addr, ph, key).await?;
                    } else {
                        // not in memory, fetch from db with spawn in case blocking me
                        let mut me = self.clone();
                        let key = key.to_owned();
                        tokio::spawn(async move {
                            allow_err!(me.handle_udp_punch_hole_request(addr, ph, &key).await);
                        });
                    }
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    self.handle_hole_sent(phs, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    self.handle_local_addr(la, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if let Some(response) = self.pro_license_failure_response(addr) {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_punch_hole_response(response);
                        Self::send_to_sink(sink, msg_out).await;
                        return true;
                    }
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if let Some(peer) = self.pm.get_for_rendezvous(&rf.id).await {
                        let peer = peer.read().await;
                        if (peer.last_reg_time.elapsed().as_millis() as i32) < REG_TIMEOUT {
                            let mut msg_out = RendezvousMessage::new();
                            rf.socket_addr = AddrMangle::encode(addr).into();
                            msg_out.set_request_relay(rf);
                            self.tx
                                .send(Data::Msg(msg_out.into(), peer.socket_addr))
                                .ok();
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }
                _ => {}
            }
        }
        false
    }

    async fn register_pk(&mut self, rk: RegisterPk, addr: SocketAddr) -> RegistrationResult {
        if rk.uuid.is_empty() || rk.pk.is_empty() || rk.id.len() < 6 {
            return RegistrationResult::UuidMismatch;
        }
        let id = rk.id;
        let ip = addr.ip().to_string();
        if !self.check_ip_blocker(&ip, &id).await {
            return RegistrationResult::TooFrequent;
        }

        let cached = self.pm.get_in_memory(&id).await;
        let reg_pk = if let Some(peer) = cached.as_ref() {
            let mut peer = peer.write().await;
            if peer.uuid != rk.uuid || (peer.info.ip != ip && peer.pk != rk.pk) || !peer.admitted {
                return RegistrationResult::UuidMismatch;
            }
            if peer.reg_pk.1.elapsed() >= PENDING_REGISTRATION_WINDOW {
                peer.reg_pk = (0, Instant::now());
            }
            if peer.reg_pk.0 >= 3 {
                return RegistrationResult::TooFrequent;
            }
            peer.reg_pk.0 += 1;
            peer.reg_pk.1 = Instant::now();
            peer.reg_pk
        } else {
            match self.pending_registrations.lock().await.record(&id, &ip) {
                Some(state) => state,
                None => return RegistrationResult::TooFrequent,
            }
        };

        let info = serde_json::to_string(&PeerInfo { ip: ip.clone() }).unwrap_or_default();
        let admission = match self
            .pm
            .db
            .admit_device(&id, &rk.uuid, &rk.pk, &info, &ip, self.inner.pro_enabled)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                log::error!("设备 {} 数据库准入失败: {:#}", id, err);
                return RegistrationResult::ServerError;
            }
        };

        match admission {
            DeviceAdmissionResult::Rejected(DeviceAdmissionFailure::UuidMismatch) => {
                RegistrationResult::UuidMismatch
            }
            DeviceAdmissionResult::Rejected(DeviceAdmissionFailure::LicenseMismatch) => {
                RegistrationResult::LicenseMismatch
            }
            DeviceAdmissionResult::Rejected(DeviceAdmissionFailure::LicenseOveruse {
                current,
                max,
            }) => {
                license::log_overuse_limited(&id, current, max);
                RegistrationResult::LicenseOveruse { current, max }
            }
            DeviceAdmissionResult::Admitted(admission) => {
                let transferred_reg_pk = if cached.is_some() {
                    reg_pk
                } else {
                    self.pending_registrations
                        .lock()
                        .await
                        .take(&id, &ip)
                        .unwrap_or(reg_pk)
                };
                if admission.previous_ip.as_deref() != Some(ip.as_str())
                    && admission.previous_ip.is_some()
                {
                    self.record_ip_change(&id, &ip).await;
                }
                if self
                    .pm
                    .insert_admitted(id.clone(), admission.peer, addr, transferred_reg_pk)
                    .await
                    .is_none()
                {
                    log::warn!("设备 {} 的准入结果在写入缓存前已失效，请客户端重试", id);
                    return RegistrationResult::ServerError;
                }
                if admission.newly_counted {
                    if let Some((current, max)) = admission.usage_after {
                        license::log_quota_usage_event("设备准入", current, max);
                    }
                }
                RegistrationResult::Ok
            }
        }
    }

    async fn record_ip_change(&self, id: &str, ip: &str) {
        let mut lock = IP_CHANGES.lock().await;
        if let Some((tm, ips)) = lock.get_mut(id) {
            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                *tm = Instant::now();
                ips.clear();
                ips.insert(ip.to_owned(), 1);
            } else if let Some(value) = ips.get_mut(ip) {
                *value += 1;
            } else {
                ips.insert(ip.to_owned(), 1);
            }
        } else {
            lock.insert(
                id.to_owned(),
                (Instant::now(), HashMap::from([(ip.to_owned(), 1)])),
            );
        }
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = self.refresh_addr_state(&id, socket_addr).await;
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    async fn refresh_addr_state(
        &self,
        id: &str,
        socket_addr: SocketAddr,
    ) -> (bool, Option<String>) {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(id).await {
            let (ip_change, previous, expired, expected_guid) = {
                let old = old.read().await;
                let ip = socket_addr.ip();
                let ip_change = (if old.socket_addr.port() != 0 {
                    ip != old.socket_addr.ip()
                } else {
                    ip.to_string() != old.info.ip
                }) && !ip.is_loopback();
                let previous = if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                };
                (
                    ip_change,
                    previous,
                    old.last_reg_time.elapsed().as_millis() as i32 >= REG_TIMEOUT,
                    old.guid.clone(),
                )
            };
            if ip_change {
                (true, Some(previous))
            } else {
                match self.pm.db.touch_admitted_device(id, &expected_guid).await {
                    Ok(true) => {
                        let mut old = old.write().await;
                        old.socket_addr = socket_addr;
                        old.last_reg_time = Instant::now();
                        (false, None)
                    }
                    Ok(false) => {
                        if let Err(err) =
                            self.pm.invalidate_if_not_admitted(id, &expected_guid).await
                        {
                            log::error!("心跳发现设备 {} 未准入，缓存失效失败: {:#}", id, err);
                        }
                        (true, None)
                    }
                    Err(err) => {
                        log::error!("设备 {} 心跳持久化失败: {:#}", id, err);
                        // 数据库失败绝不刷新内存；仅保留此前 30 秒窗口的剩余时间。
                        (expired, None)
                    }
                }
            }
        } else {
            (true, None)
        };
        (request_pk, ip_change)
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if self.inner.pro_enabled {
            if let Some(response) = self.pro_license_failure_response(addr) {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(response);
                return Ok((msg_out, None));
            }
        } else if !key.is_empty() && ph.licence_key != key {
            log::warn!(
                "Authentication failed from {} for peer {} - invalid key",
                addr,
                ph.id
            );
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get_for_rendezvous(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i32, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }

            // record punch hole request (from addr -> peer id/peer_addr)
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let to_id_clone = id.clone();
                let mut lock = PUNCH_REQS.lock().await;
                let mut dup = false;
                for e in lock.iter().rev().take(30) {
                    // only check recent tail subset for speed
                    if e.from_ip == from_ip && e.to_id == to_id_clone {
                        if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC {
                            dup = true;
                        }
                        break;
                    }
                }
                if !dup {
                    lock.push(PunchReqEntry {
                        tm: Instant::now(),
                        from_ip,
                        to_ip,
                        to_id: to_id_clone,
                    });
                }
            }

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    fn pro_license_failure_response(&self, addr: SocketAddr) -> Option<PunchHoleResponse> {
        if !self.inner.pro_enabled {
            return None;
        }
        let failure = match license::check_license_valid_for_connection() {
            Ok(()) => return None,
            Err(LicenseError::Overuse { current, max }) => {
                log::warn!(
                    "许可证设备配额超限 {}/{}，拒绝来自 {} 的连接",
                    current,
                    max,
                    addr
                );
                punch_hole_response::Failure::LICENSE_OVERUSE
            }
            Err(LicenseError::NoLicense) => {
                log::warn!("Pro 许可证未配置，拒绝来自 {} 的连接", addr);
                punch_hole_response::Failure::LICENSE_MISMATCH
            }
            Err(LicenseError::Expired(expired_at)) => {
                log::warn!("Pro 许可证已过期({})，拒绝来自 {} 的连接", expired_at, addr);
                punch_hole_response::Failure::LICENSE_MISMATCH
            }
            Err(err) => {
                log::warn!("许可证检查失败，拒绝来自 {} 的连接: {}", addr, err);
                punch_hole_response::Failure::LICENSE_MISMATCH
            }
        };
        Some(PunchHoleResponse {
            failure: failure.into(),
            ..Default::default()
        })
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_for_rendezvous(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i32;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.tx.send(Data::Msg(msg.into(), addr))?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg {
                    lock.clear();
                } else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds
                        .next()
                        .and_then(|x| x.parse::<usize>().ok())
                        .unwrap_or(10);
                    if page_size == 0 {
                        page_size = 10;
                    }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(
                            res,
                            "{} {} -> {}@{}",
                            event_iso, e.from_ip, e.to_id, e.to_ip
                        );
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |req: &Request, response: Response| {
                let headers = req.headers();
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip {
                    if ip.contains('.') {
                        addr = format!("{ip}:0").parse().unwrap_or(addr);
                    } else {
                        addr = format!("[{ip}]:0").parse().unwrap_or(addr);
                    }
                }
                Ok(response)
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            while let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await {
                if let tungstenite::Message::Binary(bytes) = msg {
                    if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                        break;
                    }
                }
            }
        } else {
            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a));
            while let Ok(Some(Ok(bytes))) = timeout(30_000, b.next()).await {
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get_for_rendezvous(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> (String, Option<sign::SecretKey>) {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0);
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        (key, out_sk)
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_registration_result(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    result: RegistrationResult,
) -> ResultType<()> {
    let res = protocol_registration_result(result);
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

/// 上游 RegisterPkResponse 尚未给许可证错误分配正式编号。
/// 在共享协议落地前统一映射为 SERVER_ERROR，避免占用 NOT_DEPLOYED=8 或擅用 9/10。
fn protocol_registration_result(result: RegistrationResult) -> register_pk_response::Result {
    match result {
        RegistrationResult::Ok => register_pk_response::Result::OK,
        RegistrationResult::UuidMismatch => register_pk_response::Result::UUID_MISMATCH,
        RegistrationResult::TooFrequent => register_pk_response::Result::TOO_FREQUENT,
        RegistrationResult::LicenseMismatch
        | RegistrationResult::LicenseOveruse { .. }
        | RegistrationResult::ServerError => register_pk_response::Result::SERVER_ERROR,
    }
}

async fn create_udp_listener(port: i32, rmem: usize) -> ResultType<FramedSocket> {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(port: i32) -> ResultType<TcpListener> {
    let s = listen_any(port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use sqlx::{Connection, Executor, SqliteConnection};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn protocol_mapping_does_not_occupy_unapproved_numbers() {
        assert_eq!(
            protocol_registration_result(RegistrationResult::LicenseMismatch),
            register_pk_response::Result::SERVER_ERROR
        );
        assert_eq!(
            protocol_registration_result(RegistrationResult::LicenseOveruse { current: 1, max: 1 }),
            register_pk_response::Result::SERVER_ERROR
        );
    }

    #[test]
    fn pro_disabled_register_peer_pk_punch_relay_and_key_exchange_keep_oss_behavior() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            license::clear_license();
            let path = temp_db_path("oss-regression");
            let db = Database::new(&path).await.unwrap();
            let mut server = test_server(db, false);
            let peer_addr: SocketAddr = "127.0.0.1:30100".parse().unwrap();
            let result = server
                .register_pk(
                    RegisterPk {
                        id: "device-oss".to_string(),
                        uuid: Bytes::from_static(b"uuid-oss"),
                        pk: Bytes::from_static(b"pk-oss"),
                        ..Default::default()
                    },
                    peer_addr,
                )
                .await;
            assert_eq!(result, RegistrationResult::Ok);
            assert!(server.pm.is_in_memory("device-oss").await);
            assert!(server.pro_license_failure_response(peer_addr).is_none());
            let (request_pk, _) = server.refresh_addr_state("device-oss", peer_addr).await;
            assert!(!request_pk);

            let (_, target) = server
                .handle_punch_hole_request(
                    "127.0.0.1:30200".parse().unwrap(),
                    PunchHoleRequest {
                        id: "device-oss".to_string(),
                        ..Default::default()
                    },
                    "",
                    false,
                )
                .await
                .unwrap();
            assert_eq!(target, Some(peer_addr));

            let (relay_tx, mut relay_rx) = mpsc::unbounded_channel();
            server.tx = relay_tx;
            let mut relay_message = RendezvousMessage::new();
            relay_message.set_request_relay(RequestRelay {
                id: "device-oss".to_string(),
                ..Default::default()
            });
            let mut sink = None;
            assert!(
                server
                    .handle_tcp(
                        &relay_message.write_to_bytes().unwrap(),
                        &mut sink,
                        "127.0.0.1:30201".parse().unwrap(),
                        "",
                        false,
                    )
                    .await
            );
            assert!(
                matches!(relay_rx.recv().await, Some(Data::Msg(_, target)) if target == peer_addr)
            );

            let mut key_exchange = RendezvousMessage::new();
            key_exchange.set_key_exchange(KeyExchange {
                keys: vec![Bytes::from_static(b"unchanged-key")],
                ..Default::default()
            });
            let mut sink = None;
            assert!(
                !server
                    .handle_tcp(
                        &key_exchange.write_to_bytes().unwrap(),
                        &mut sink,
                        "127.0.0.1:30202".parse().unwrap(),
                        "",
                        false,
                    )
                    .await
            );
            cleanup(&path);
        });
    }

    #[test]
    fn database_failure_does_not_leave_peer_map_placeholder() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("db-failure-no-placeholder");
            let db = Database::new(&path).await.unwrap();
            let mut server = test_server(db, false);
            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DROP TABLE devices").await.unwrap();

            let result = server
                .register_pk(
                    RegisterPk {
                        id: "device-fail".to_string(),
                        uuid: Bytes::from_static(b"uuid-fail"),
                        pk: Bytes::from_static(b"pk-fail"),
                        ..Default::default()
                    },
                    "127.0.0.1:30300".parse().unwrap(),
                )
                .await;
            assert_eq!(result, RegistrationResult::ServerError);
            assert!(!server.pm.is_in_memory("device-fail").await);
            cleanup(&path);
        });
    }

    #[test]
    fn still_inactive_command_consumer_preserves_issue_7_behavior() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("still-inactive-command");
            let db = Database::new(&path).await.unwrap();
            db.insert_peer("device-command", b"uuid", b"pk", "{}")
                .await
                .unwrap();
            let server = test_server(db.clone(), false);
            server
                .pm
                .get_for_rendezvous("device-command")
                .await
                .unwrap();
            db.set_device_inactive("device-command").await.unwrap();

            let (ack, result) = tokio::sync::oneshot::channel();
            server
                .handle_device_invalidation_command(DeviceInvalidationCommand {
                    device_id: "device-command".to_string(),
                    predicate: DeviceInvalidationPredicate::StillInactive,
                    ack,
                })
                .await;

            assert_eq!(result.await.unwrap().unwrap(), InvalidationResult::Removed);
            assert!(server.pm.get_in_memory("device-command").await.is_none());
            cleanup(&path);
        });
    }

    #[test]
    fn heartbeat_database_failure_never_refreshes_memory_window() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("heartbeat-db-failure");
            let db = Database::new(&path).await.unwrap();
            let mut server = test_server(db, false);
            let addr: SocketAddr = "127.0.0.1:30400".parse().unwrap();
            assert_eq!(
                server
                    .register_pk(
                        RegisterPk {
                            id: "device-heartbeat".to_string(),
                            uuid: Bytes::from_static(b"uuid-heartbeat"),
                            pk: Bytes::from_static(b"pk-heartbeat"),
                            ..Default::default()
                        },
                        addr,
                    )
                    .await,
                RegistrationResult::Ok
            );
            let peer = server.pm.get_in_memory("device-heartbeat").await.unwrap();
            let before = peer.read().await.last_reg_time;
            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DROP TABLE devices").await.unwrap();

            let (request_pk, _) = server.refresh_addr_state("device-heartbeat", addr).await;
            assert!(!request_pk);
            assert_eq!(peer.read().await.last_reg_time, before);

            let expired = Instant::now() - Duration::from_secs(31);
            peer.write().await.last_reg_time = expired;
            let (request_pk, _) = server.refresh_addr_state("device-heartbeat", addr).await;
            assert!(request_pk);
            assert_eq!(peer.read().await.last_reg_time, expired);
            cleanup(&path);
        });
    }

    #[test]
    fn heartbeat_guid_change_invalidates_old_arc() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let path = temp_db_path("heartbeat-guid-change");
            let db = Database::new(&path).await.unwrap();
            let mut server = test_server(db.clone(), false);
            let addr: SocketAddr = "127.0.0.1:30410".parse().unwrap();
            assert_eq!(
                server
                    .register_pk(
                        RegisterPk {
                            id: "device-guid-change".to_string(),
                            uuid: Bytes::from_static(b"uuid-old"),
                            pk: Bytes::from_static(b"pk-old"),
                            ..Default::default()
                        },
                        addr,
                    )
                    .await,
                RegistrationResult::Ok
            );
            let old = server.pm.get_in_memory("device-guid-change").await.unwrap();

            let mut conn = SqliteConnection::connect(&path).await.unwrap();
            conn.execute("DELETE FROM devices WHERE device_id = 'device-guid-change'")
                .await
                .unwrap();
            drop(conn);
            let new_guid = db
                .insert_peer("device-guid-change", b"uuid-new", b"pk-new", "{}")
                .await
                .unwrap();

            let (request_pk, _) = server.refresh_addr_state("device-guid-change", addr).await;
            assert!(request_pk);
            assert!(server
                .pm
                .get_in_memory("device-guid-change")
                .await
                .is_none());

            let current = server
                .pm
                .get_for_rendezvous("device-guid-change")
                .await
                .unwrap();
            assert_eq!(current.read().await.guid, new_guid);
            assert!(!Arc::ptr_eq(&old, &current));
            cleanup(&path);
        });
    }

    fn test_server(db: Database, pro_enabled: bool) -> RendezvousServer {
        let (tx, _rx) = mpsc::unbounded_channel();
        RendezvousServer {
            tcp_punch: Default::default(),
            pm: PeerMap::from_database(db),
            tx,
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Default::default(),
            inner: Arc::new(Inner {
                serial: 0,
                version: String::new(),
                software_url: String::new(),
                mask: None,
                local_ip: String::new(),
                sk: None,
                pro_enabled,
            }),
            pending_registrations: Default::default(),
        }
    }

    fn temp_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rustdesk-rendezvous-{name}-{nanos}.sqlite3"))
            .to_string_lossy()
            .to_string()
    }

    fn cleanup(path: &str) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(format!("{path}-shm")).ok();
        std::fs::remove_file(format!("{path}-wal")).ok();
    }
}
