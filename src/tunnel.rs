//! 隧道控制中心：维护一条 SSH 主连接，管理多个本地端口监听的动态启停。
//! Step 4：新增实时速率统计、断线检测与自动重连。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, Handle};
use russh::keys::known_hosts::check_known_hosts;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// SSH 会话事件处理器：负责服务器主机密钥校验（防中间人攻击）
#[derive(Clone)]
pub(crate) struct SshHandler {
    host: String,
    port: u16,
    /// false 时跳过 known_hosts 校验（仅测试/内网使用）
    check_host_key: bool,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if !self.check_host_key {
            return Ok(true);
        }
        let key = server_public_key.public_key();
        match check_known_hosts(&self.host, self.port, &key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                eprintln!("[警告] {0} 不在 known_hosts 中，首次连接将信任该主机密钥", self.host);
                Ok(true)
            }
            Err(e) => {
                eprintln!("[错误] known_hosts 校验失败（主机密钥已变更？）：{e}");
                Ok(false)
            }
        }
    }
}

/// 连接参数（重连时复用）
#[derive(Clone)]
pub(crate) struct ConnectParams {
    pub user: String,
    pub host: String,
    pub ssh_port: u16,
    pub key_path: std::path::PathBuf,
    pub check_host_key: bool,
}

/// 连接状态
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ConnectionStatus {
    Connected,
    /// 重连中，参数为已尝试次数
    Reconnecting(usize),
    Disconnected,
}

/// 单条隧道（本地端口监听）的运行时状态
struct TunnelEntry {
    remote_host: String,
    remote_port: u32,
    /// 当前活动的转发连接数
    connections: Arc<AtomicUsize>,
    /// 累计转发字节：rx=远端→本地，tx=本地→远端
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    /// 监听循环任务；abort 即释放本地端口
    task: JoinHandle<()>,
}

/// 向外部（CLI/TUI）暴露的隧道快照
#[derive(Clone)]
pub(crate) struct TunnelInfo {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u32,
    pub connections: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
}

/// 隧道控制中心：持有 SSH 主连接句柄 + 隧道表
pub(crate) struct TunnelManager {
    params: ConnectParams,
    handle: Arc<Mutex<Handle<SshHandler>>>,
    tunnels: HashMap<u16, TunnelEntry>,
    status: ConnectionStatus,
    /// 速率计算的上一采样点
    last_rx: HashMap<u16, u64>,
    last_tx: HashMap<u16, u64>,
    last_sample: Instant,
}

/// 单个转发连接的中继：申请一条 direct-tcpip 通道后，切分为读写半，
/// 锁只在开通道期间持有，中继过程并发进行并累计字节计数。
async fn relay(
    handle: &Handle<SshHandler>,
    mut stream: TcpStream,
    remote_host: &str,
    remote_port: u32,
    originator_host: &str,
    originator_port: u32,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = handle
        .channel_open_direct_tcpip(remote_host, remote_port, originator_host, originator_port)
        .await?;
    let (mut read_half, write_half) = channel.split();
    let mut writer = write_half.make_writer();
    let mut reader = read_half.make_reader();

    let mut stream_eof = false;
    let mut buf = vec![0u8; 65536];
    let mut buf2 = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = stream.read(&mut buf), if !stream_eof => {
                match r {
                    Ok(0) => {
                        stream_eof = true;
                        writer.shutdown().await?;
                    }
                    Ok(n) => {
                        tx_bytes.fetch_add(n as u64, Ordering::SeqCst);
                        writer.write_all(&buf[..n]).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            r = reader.read(&mut buf2) => {
                match r {
                    Ok(0) => break,
                    Ok(n) => {
                        rx_bytes.fetch_add(n as u64, Ordering::SeqCst);
                        stream.write_all(&buf2[..n]).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(())
}

/// 隧道监听循环：持续 accept 本地连接，每个连接开一条 direct-tcpip 通道转发。
/// 该任务被 abort 时 listener 随之 drop，本地端口被释放；
/// 已建立的转发连接是独立任务，不受影响（与 ssh -O cancel 语义一致）。
async fn listen_loop(
    listener: TcpListener,
    handle: Arc<Mutex<Handle<SshHandler>>>,
    local_port: u16,
    remote_host: String,
    remote_port: u32,
    connections: Arc<AtomicUsize>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
) {
    println!("[+] 隧道 {local_port} -> {remote_host}:{remote_port}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[错误] 隧道 {local_port} accept 失败：{e}");
                continue;
            }
        };
        let handle = Arc::clone(&handle);
        let connections = Arc::clone(&connections);
        let rx_bytes = Arc::clone(&rx_bytes);
        let tx_bytes = Arc::clone(&tx_bytes);
        let (host, port) = (remote_host.clone(), remote_port);
        let peer_addr = peer.ip().to_string();
        let peer_port = peer.port().into();
        tokio::spawn(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            // 锁仅在申请通道期间持有，中继过程不占用 session
            let handle = handle.lock().await;
            let result = relay(&handle, stream, &host, port, &peer_addr, peer_port, rx_bytes, tx_bytes).await;
            connections.fetch_sub(1, Ordering::SeqCst);
            if let Err(e) = result {
                eprintln!("[-] 隧道 {local_port} {peer} 转发失败：{e}");
            }
        });
    }
}

impl TunnelManager {
    /// 建立 SSH 主连接（含认证）
    async fn connect_handle(params: &ConnectParams) -> Result<Handle<SshHandler>, String> {
        let key = load_secret_key(&params.key_path, None)
            .map_err(|e| format!("加载私钥 {} 失败：{e}", params.key_path.display()))?;
        let key = Arc::new(key);

        let config = Arc::new(client::Config::default());
        let mut session = client::connect(
            config,
            (params.host.as_str(), params.ssh_port),
            SshHandler {
                host: params.host.clone(),
                port: params.ssh_port,
                check_host_key: params.check_host_key,
            },
        )
        .await
        .map_err(|e| format!("连接 {0}:{1} 失败：{e}", params.host, params.ssh_port))?;
        let auth = session
            .authenticate_publickey(
                &params.user,
                PrivateKeyWithHashAlg::new(key, session.best_supported_rsa_hash().await.map_err(|e| format!("获取服务器 RSA 算法失败：{e}"))?.flatten()),
            )
            .await
            .map_err(|e| format!("SSH 认证请求失败：{e}"))?;
        if !auth.success() {
            return Err(format!("SSH 公钥认证失败（{}@{}）", params.user, params.host));
        }
        Ok(session)
    }

    /// 建立 SSH 主连接并初始化管理器
    pub(crate) async fn connect(params: ConnectParams) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let handle = Self::connect_handle(&params)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        Ok(Self {
            params,
            handle: Arc::new(Mutex::new(handle)),
            tunnels: HashMap::new(),
            status: ConnectionStatus::Connected,
            last_rx: HashMap::new(),
            last_tx: HashMap::new(),
            last_sample: Instant::now(),
        })
    }

    pub(crate) fn status(&self) -> ConnectionStatus {
        self.status
    }


    /// 检测主连接是否断开；若断开则自动重连（指数退避，最多 5 次）
    pub(crate) async fn check_and_reconnect(&mut self) -> ConnectionStatus {
        if self.status != ConnectionStatus::Connected {
            return self.status; // 重连中/已离线，交给重连流程
        }
        let closed = self.handle.lock().await.is_closed();
        if !closed {
            return self.status;
        }
        eprintln!("[!] SSH 主连接断开，尝试重连…");
        for attempt in 1..=5 {
            self.status = ConnectionStatus::Reconnecting(attempt);
            match Self::connect_handle(&self.params).await {
                Ok(new_handle) => {
                    *self.handle.lock().await = new_handle;
                    self.status = ConnectionStatus::Connected;
                    eprintln!("[OK] 已重连，隧道恢复");
                    return self.status;
                }
                Err(e) => {
                    eprintln!("[!] 重连第 {attempt} 次失败：{e}");
                    let wait = Duration::from_secs(1u64 << attempt.min(4));
                    tokio::time::sleep(wait).await;
                }
            }
        }
        self.status = ConnectionStatus::Disconnected;
        self.status
    }

    /// 新增一条隧道：绑定本地端口，启动监听循环
    pub(crate) async fn add(
        &mut self,
        local_port: u16,
        remote_host: &str,
        remote_port: u32,
    ) -> Result<(), String> {
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|e| format!("本地端口 {local_port} 绑定失败：{e}"))?;
        let connections = Arc::new(AtomicUsize::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(listen_loop(
            listener,
            Arc::clone(&self.handle),
            local_port,
            remote_host.to_string(),
            remote_port,
            Arc::clone(&connections),
            Arc::clone(&rx_bytes),
            Arc::clone(&tx_bytes),
        ));
        self.tunnels.insert(
            local_port,
            TunnelEntry {
                remote_host: remote_host.to_string(),
                remote_port,
                connections,
                rx_bytes,
                tx_bytes,
                task,
            },
        );
        Ok(())
    }

    /// 停止一条隧道：注销监听任务、释放本地端口；已有转发连接继续
    pub(crate) async fn remove(&mut self, local_port: u16) -> Result<(), String> {
        let entry = self
            .tunnels
            .remove(&local_port)
            .ok_or_else(|| format!("隧道 {local_port} 不存在"))?;
        entry.task.abort();
        println!("[-] 隧道 {local_port} 已停止");
        Ok(())
    }

    /// 当前所有隧道快照（含实时速率，基于上一次采样计算）
    pub(crate) fn list(&mut self) -> Vec<TunnelInfo> {
        let now = Instant::now();
        let dt = now.duration_since(self.last_sample).as_secs_f64().max(0.001);
        let mut v: Vec<TunnelInfo> = self
            .tunnels
            .iter()
            .map(|(&local_port, e)| {
                let rx = e.rx_bytes.load(Ordering::SeqCst);
                let tx = e.tx_bytes.load(Ordering::SeqCst);
                let rx_prev = self.last_rx.get(&local_port).copied().unwrap_or(0);
                let tx_prev = self.last_tx.get(&local_port).copied().unwrap_or(0);
                let rx_rate = ((rx.saturating_sub(rx_prev)) as f64 / dt) as u64;
                let tx_rate = ((tx.saturating_sub(tx_prev)) as f64 / dt) as u64;
                self.last_rx.insert(local_port, rx);
                self.last_tx.insert(local_port, tx);
                TunnelInfo {
                    local_port,
                    remote_host: e.remote_host.clone(),
                    remote_port: e.remote_port,
                    connections: e.connections.load(Ordering::SeqCst),
                    rx_bytes: rx,
                    tx_bytes: tx,
                    rx_rate,
                    tx_rate,
                }
            })
            .collect();
        self.last_rx.retain(|p, _| self.tunnels.contains_key(p));
        self.last_tx.retain(|p, _| self.tunnels.contains_key(p));
        self.last_sample = now;
        v.sort_by_key(|t| t.local_port);
        v
    }

    /// 优雅断开 SSH 主连接
    pub(crate) async fn shutdown(&mut self) {
        for (_port, entry) in self.tunnels.drain() {
            entry.task.abort();
        }
        let _ = self
            .handle
            .lock()
            .await
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await;
    }
}

// ---------- 后台管理任务（TUI 协作层） ----------

/// 前台（TUI）发往管理任务的控制指令
pub(crate) enum Command {
    Add {
        local_port: u16,
        remote_host: String,
        remote_port: u32,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Remove {
        local_port: u16,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Quit,
}

/// 管理任务推送给前台的状态事件
pub(crate) enum Event {
    State {
        status: ConnectionStatus,
        tunnels: Vec<TunnelInfo>,
    },
}

/// 管理任务主循环：串行执行控制指令，周期性推送状态快照，
/// 检测到 SSH 断开时自动重连。退出时优雅关闭主连接。
pub(crate) async fn manager_loop(
    mut mgr: TunnelManager,
    mut rx: tokio::sync::mpsc::Receiver<Command>,
    events: tokio::sync::mpsc::UnboundedSender<Event>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let status = mgr.check_and_reconnect().await;
                let _ = events.send(Event::State { status, tunnels: mgr.list() });
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break }; // 发送端全部关闭
                match cmd {
                    Command::Add { local_port, remote_host, remote_port, reply } => {
                        let r = mgr.add(local_port, &remote_host, remote_port).await;
                        let _ = reply.send(r);
                    }
                    Command::Remove { local_port, reply } => {
                        let r = mgr.remove(local_port).await;
                        let _ = reply.send(r);
                    }
                    Command::Quit => break,
                }
                let _ = events.send(Event::State { status: mgr.status(), tunnels: mgr.list() });
            }
        }
    }
    mgr.shutdown().await;
}