//! 隧道控制中心：维护一条 SSH 主连接，管理多个本地端口监听的动态启停。
//! Step 4：新增实时速率统计、断线检测与自动重连。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, Handle};
use russh::keys::known_hosts::check_known_hosts;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
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

/// 单条隧道的日志（有序环形缓冲，最多保留 [`LOG_CAPACITY`] 条）
pub(crate) type TunnelLog = Arc<std::sync::Mutex<VecDeque<String>>>;
const LOG_CAPACITY: usize = 200;

fn log_push(log: &TunnelLog, msg: String) {
    if let Ok(mut l) = log.lock() {
        if l.len() >= LOG_CAPACITY {
            l.pop_front();
        }
        l.push_back(msg);
    }
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
    /// 该隧道的事件日志
    log: TunnelLog,
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
    /// 该隧道的事件日志（旧→新）
    pub log: Vec<String>,
}

/// 远端发现的监听端口
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemotePort {
    pub port: u16,
    pub process: String,
}

/// 隧道控制中心：持有 SSH 主连接句柄 + 隧道表
pub(crate) struct TunnelManager {
    params: ConnectParams,
    handle: Arc<RwLock<Handle<SshHandler>>>,
    tunnels: HashMap<u16, TunnelEntry>,
    status: Arc<std::sync::Mutex<ConnectionStatus>>,
    /// 速率计算的上一采样点
    last_rx: HashMap<u16, u64>,
    last_tx: HashMap<u16, u64>,
    last_sample: Instant,
    /// 上次 keepalive 探测时间（闲置时维持连接活性并检测半开断链）
    last_keepalive: Instant,
}

/// 单个转发连接的中继：锁内只做 channel open 并切分读写半，
/// 随后释放锁，双向中继完全并发进行（互不阻塞），并累计字节计数。
async fn relay(
    session: Arc<RwLock<Handle<SshHandler>>>,
    mut stream: TcpStream,
    remote_host: &str,
    remote_port: u32,
    originator_host: &str,
    originator_port: u32,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = {
        // 读锁可被多个连接并发持有：channel open 的确认等待不再互相阻塞
        let handle = session.read().await;
        handle
            .channel_open_direct_tcpip(remote_host, remote_port, originator_host, originator_port)
            .await?
    };
    let (mut read_half, write_half) = channel.split();
    // 锁已释放：make_writer/make_reader 基于克隆的 sender/receiver，不依赖会话锁
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
    handle: Arc<RwLock<Handle<SshHandler>>>,
    remote_host: String,
    remote_port: u32,
    connections: Arc<AtomicUsize>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    log: TunnelLog,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log_push(&log, format!("accept 失败：{e}"));
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let handle = Arc::clone(&handle);
        let connections = Arc::clone(&connections);
        let rx_bytes = Arc::clone(&rx_bytes);
        let tx_bytes = Arc::clone(&tx_bytes);
        let log = Arc::clone(&log);
        let (host, port) = (remote_host.clone(), remote_port);
        let peer_addr = peer.ip().to_string();
        let peer_port = peer.port().into();
        tokio::spawn(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            log_push(&log, format!("{peer} 接入"));
            // 锁只覆盖 channel open 阶段（relay 内部），中继过程不占用 session
            let result = relay(handle, stream, &host, port, &peer_addr, peer_port, rx_bytes, tx_bytes).await;
            connections.fetch_sub(1, Ordering::SeqCst);
            match result {
                Ok(()) => log_push(&log, format!("{peer} 连接结束")),
                Err(e) => log_push(&log, format!("{peer} 转发失败：{e}")),
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

        let config = Arc::new(client::Config {
            nodelay: true,
            ..Default::default()
        });
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
            handle: Arc::new(RwLock::new(handle)),
            tunnels: HashMap::new(),
            status: Arc::new(std::sync::Mutex::new(ConnectionStatus::Connected)),
            last_rx: HashMap::new(),
            last_tx: HashMap::new(),
            last_sample: Instant::now(),
            last_keepalive: Instant::now(),
        })
    }

    pub(crate) fn status(&self) -> ConnectionStatus {
        *self.status.lock().unwrap()
    }


    /// 检测主连接是否断开；若断开则自动重连（指数退避，最多 5 次）
    /// 检测 SSH 主连接是否断开；若断开则启动后台重连任务（不阻塞调用方）。
    /// 重连任务串行尝试最多 5 次（指数退避），完成后更新共享状态。
    pub(crate) async fn check_and_reconnect(&mut self) -> ConnectionStatus {
        let now = self.status();
        if now != ConnectionStatus::Connected {
            return now; // 已有重连任务在跑或已离线
        }
        // 30s 一次的存活探测：空闲时维持连接活跃，半开断链时能感知
        let need_probe = self.last_keepalive.elapsed() >= Duration::from_secs(30);
        if need_probe {
            self.last_keepalive = Instant::now();
        }
        let closed = {
            let handle = self.handle.read().await;
            if handle.is_closed() {
                true
            } else if need_probe {
                // ping 带 10s 超时：失败视为连接已死（半开连接）
                matches!(
                    tokio::time::timeout(Duration::from_secs(10), handle.send_ping()).await,
                    Err(_) | Ok(Err(_))
                )
            } else {
                false
            }
        };
        if !closed {
            return now;
        }
        // 启动后台重连：命令循环不再被退避 sleep 阻塞
        *self.status.lock().unwrap() = ConnectionStatus::Reconnecting(0);
        let params = self.params.clone();
        let handle = Arc::clone(&self.handle);
        let status = Arc::clone(&self.status);
        tokio::spawn(async move {
            for attempt in 1..=5 {
                *status.lock().unwrap() = ConnectionStatus::Reconnecting(attempt);
                match TunnelManager::connect_handle(&params).await {
                    Ok(new_handle) => {
                        *handle.write().await = new_handle;
                        *status.lock().unwrap() = ConnectionStatus::Connected;
                        return;
                    }
                    Err(_) => {
                        let wait = Duration::from_secs(1u64 << attempt.min(4));
                        tokio::time::sleep(wait).await;
                    }
                }
            }
            *status.lock().unwrap() = ConnectionStatus::Disconnected;
        });
        ConnectionStatus::Reconnecting(0)
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
        let log: TunnelLog = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        log_push(&log, format!("隧道已创建：{local_port} -> {remote_host}:{remote_port}"));
        let task = tokio::spawn(listen_loop(
            listener,
            Arc::clone(&self.handle),
            remote_host.to_string(),
            remote_port,
            Arc::clone(&connections),
            Arc::clone(&rx_bytes),
            Arc::clone(&tx_bytes),
            Arc::clone(&log),
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
                log,
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
                    log: e.log.lock().map(|l| l.iter().cloned().collect()).unwrap_or_default(),
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
        *self.status.lock().unwrap() = ConnectionStatus::Disconnected;
        for (_port, entry) in self.tunnels.drain() {
            entry.task.abort();
        }
        let _ = self
            .handle
            .write()
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
    /// 扫描远端监听端口（VSCode 式端口发现）
    ScanPorts {
        reply: tokio::sync::oneshot::Sender<Vec<RemotePort>>,
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
                    Command::ScanPorts { reply } => {
                        let ports = scan_remote_ports(&mgr.handle).await;
                        let _ = reply.send(ports);
                    }
                    Command::Quit => break,
                }
                let _ = events.send(Event::State { status: mgr.status(), tunnels: mgr.list() });
            }
        }
    }
    mgr.shutdown().await;
}
// ---------- 远端端口发现 ----------

/// 在远端执行 `ss -tln`（fallback: netstat -tln），解析监听端口列表。
/// 失败时返回空列表。
pub(crate) async fn scan_remote_ports(
    handle: &RwLock<Handle<SshHandler>>,
) -> Vec<RemotePort> {
    let mut channel = {
        let h = handle.read().await;
        match h.channel_open_session().await {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        }
    };
    let cmd = "ss -tln 2>/dev/null || netstat -tln 2>/dev/null";
    if channel.exec(true, cmd).await.is_err() {
        return Vec::new();
    }
    let mut output = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
            Some(ChannelMsg::Eof) => break,
            Some(_) => {}
            None => break,
        }
    }
    parse_listen_ports(&String::from_utf8_lossy(&output))
}

/// 解析 `ss -tln` / `netstat -tln` 输出中的 LISTEN 端口与进程名
fn parse_listen_ports(output: &str) -> Vec<RemotePort> {
    let mut ports = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.contains("LISTEN") {
            continue;
        }
        // 进程名：ss 的 users:(("name",pid=..)) 或 netstat 的 pid/name
        let process = extract_process(line);
        // 端口：Local Address 列（第 4 个空白分隔字段）最后一个 ':' 后的数字
        let port = match line.split_whitespace().nth(3) {
            Some(local) => match local.rfind(':') {
                Some(i) => {
                    let digits: String = local[i + 1..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    digits.parse::<u16>().ok()
                }
                None => None,
            },
            None => None,
        };
        if let Some(port) = port {
            if port > 0 && !ports.iter().any(|p: &RemotePort| p.port == port) {
                ports.push(RemotePort { port, process });
            }
        }
    }
    ports.sort_by_key(|p| p.port);
    ports
}

fn extract_process(line: &str) -> String {
    // ss: users:(("sshd",pid=123,fd=4))
    if let Some(idx) = line.find("((\"") {
        let rest = &line[idx + 3..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    // netstat: 1234/sshd  （行尾 pid/name）
    if let Some(idx) = line.find("LISTEN") {
        let tail = line[idx + 6..].trim();
        if let Some(slash) = tail.find('/') {
            let name: String = tail[slash + 1..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if !name.is_empty() {
                return name;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ss_output() {
        let out = "\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22          0.0.0.0:*       users:((\"sshd\",pid=123,fd=3))
LISTEN 0      511    127.0.0.1:8848      0.0.0.0:*       users:((\"python3\",pid=456,fd=5))
LISTEN 0      5      127.0.0.1:8000      0.0.0.0:*       users:((\"python3\",pid=789,fd=3))
";
        let ports = parse_listen_ports(out);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], RemotePort { port: 22, process: "sshd".into() });
        assert_eq!(ports[1], RemotePort { port: 8000, process: "python3".into() });
        assert_eq!(ports[2], RemotePort { port: 8848, process: "python3".into() });
    }

    #[test]
    fn parse_netstat_output() {
        let out = "\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      456/cupsd
";
        let ports = parse_listen_ports(out);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0], RemotePort { port: 22, process: "sshd".into() });
        assert_eq!(ports[1], RemotePort { port: 631, process: "cupsd".into() });
    }

    #[test]
    fn dedup_and_sort() {
        let out = "LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:((\"a\",pid=1))\n\
                    LISTEN 0 1 0.0.0.0:80 0.0.0.0:* users:((\"b\",pid=2))\n\
                    LISTEN 0 1 0.0.0.0:22 0.0.0.0:* users:((\"c\",pid=3))\n";
        let ports = parse_listen_ports(out);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[1].port, 80);
    }
}
