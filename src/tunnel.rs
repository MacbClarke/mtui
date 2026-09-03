//! 隧道控制中心：维护多条 SSH 主连接，管理多个本地端口监听的动态启停与流量中继。
//! 支持多主机并发连接、密码与公钥认证、~/.ssh/config 别名解析、实时速率统计、断线检测与自动重连。

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, Handle};
use russh::keys::known_hosts::check_known_hosts;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use serde::{Deserialize, Serialize};
use ssh2_config::{ParseRule, SshConfig};
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
                // 不在 known_hosts 中，首次连接信任
                Ok(true)
            }
            Err(_) => {
                // 主机密钥校验失败（不匹配或变更）
                Ok(false)
            }
        }
    }
}

/// 展开路径开头的 `~`
pub(crate) fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    path
}

/// 获取默认私钥路径
pub(crate) fn default_key_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".ssh/id_ed25519")
}

/// 认证方式：公钥私钥文件 或 登录密码
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AuthMethod {
    KeyFile(PathBuf),
    Password(String),
}

/// SSH 连接参数
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConnectParams {
    #[serde(default)]
    pub alias: Option<String>,
    pub user: String,
    pub host: String,
    pub ssh_port: u16,
    pub auth: AuthMethod,
    pub check_host_key: bool,
}

fn default_true() -> bool {
    true
}

/// 持久化保存的单条隧道配置
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedTunnel {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// 持久化保存的单个主机及其隧道列表
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedHost {
    pub params: ConnectParams,
    #[serde(default)]
    pub tunnels: Vec<SavedTunnel>,
}

/// mtui 整体持久化配置文件结构
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AppConfig {
    #[serde(default)]
    pub hosts: Vec<SavedHost>,
}

/// 默认配置文件路径：$XDG_CONFIG_HOME/mtui/config.json 或 ~/.config/mtui/config.json
pub(crate) fn default_config_path() -> PathBuf {
    if let Ok(dir) = std::env::var("MTUI_CONFIG_DIR") {
        return PathBuf::from(dir).join("config.json");
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("mtui").join("config.json")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("mtui").join("config.json")
    } else {
        PathBuf::from("mtui_config.json")
    }
}

pub(crate) fn load_config(path: &std::path::Path) -> AppConfig {
    if !path.exists() {
        return AppConfig::default();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("[警告] 解析配置文件 {} 失败：{e}", path.display());
                AppConfig::default()
            }
        },
        Err(e) => {
            eprintln!("[警告] 读取配置文件 {} 失败：{e}", path.display());
            AppConfig::default()
        }
    }
}

pub(crate) fn save_config(cfg: &AppConfig, path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("序列化配置失败：{e}"))?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, json.as_bytes())
        .map_err(|e| format!("写入配置文件失败：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("重命名配置文件失败：{e}"))?;
    Ok(())
}

impl ConnectParams {
    pub fn display_name(&self) -> String {
        if let Some(alias) = &self.alias {
            alias.clone()
        } else {
            format!("{}@{}:{}", self.user, self.host, self.ssh_port)
        }
    }
}

/// 从 ~/.ssh/config 发现的已知主机
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshConfigHost {
    pub alias: String,
    pub host_name: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
}

impl SshConfigHost {
    pub fn to_connect_params(&self, check_host_key: bool) -> ConnectParams {
        let user = if self.user.is_empty() {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".to_string())
        } else {
            self.user.clone()
        };
        let key_path = self
            .identity_file
            .clone()
            .map(expand_tilde)
            .unwrap_or_else(default_key_path);
        ConnectParams {
            alias: Some(self.alias.clone()),
            user,
            host: self.host_name.clone(),
            ssh_port: self.port,
            auth: AuthMethod::KeyFile(key_path),
            check_host_key,
        }
    }
}

/// 读取并解析 ~/.ssh/config 中的所有已知 Host 列表
pub(crate) fn list_ssh_config_hosts() -> Vec<SshConfigHost> {
    let mut results = Vec::new();
    let config_path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".ssh/config"));
    let Some(path) = config_path else { return results };
    let Ok(content) = std::fs::read_to_string(&path) else { return results };

    let mut cfg = None;
    if let Ok(f) = std::fs::File::open(&path) {
        let mut reader = std::io::BufReader::new(f);
        if let Ok(c) = SshConfig::default().parse(
            &mut reader,
            ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
        ) {
            cfg = Some(c);
        }
    }
    let Some(cfg) = cfg else { return results };

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("Host ")
            .or_else(|| line.strip_prefix("host "))
        {
            for alias in rest.split_whitespace() {
                let alias = alias.trim();
                if alias.contains('*') || alias.contains('?') || alias.is_empty() {
                    continue;
                }
                if results.iter().any(|h: &SshConfigHost| h.alias == alias) {
                    continue;
                }
                let params = cfg.query(alias);
                let host_name = params.host_name.clone().unwrap_or_else(|| alias.to_string());
                let user = params.user.clone().unwrap_or_default();
                let port = params.port.unwrap_or(22);
                let identity_file = params
                    .identity_file
                    .as_ref()
                    .and_then(|v| v.first().cloned())
                    .map(expand_tilde);
                results.push(SshConfigHost {
                    alias: alias.to_string(),
                    host_name,
                    user,
                    port,
                    identity_file,
                });
            }
        }
    }
    results
}

/// 解析目标字符串：user@host[:port] 或别名（含 user@alias）。
pub(crate) fn resolve_target_str(
    target: &str,
    auth: Option<AuthMethod>,
    default_port: u16,
    no_host_key_check: bool,
) -> Result<ConnectParams, String> {
    let (explicit_user, rest) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, target),
    };
    let (host_str, explicit_port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = p.parse().map_err(|_| format!("端口格式错误: {p}"))?;
            (h, Some(port))
        }
        _ => (rest, None),
    };

    let mut from_config = None;
    let config_path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".ssh/config"));
    if let Some(path) = &config_path {
        if let Ok(f) = std::fs::File::open(path) {
            let mut reader = std::io::BufReader::new(f);
            if let Ok(cfg) = SshConfig::default().parse(
                &mut reader,
                ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
            ) {
                from_config = Some(cfg.query(host_str));
            }
        }
    }

    let host = from_config
        .as_ref()
        .and_then(|p| p.host_name.clone())
        .unwrap_or_else(|| host_str.to_string());
    let user = explicit_user
        .or_else(|| from_config.as_ref().and_then(|p| p.user.clone()))
        .unwrap_or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".to_string())
        });
    let ssh_port = explicit_port
        .or_else(|| from_config.as_ref().and_then(|p| p.port))
        .unwrap_or(default_port);

    let resolved_auth = match auth {
        Some(a) => a,
        None => {
            let key_path = from_config
                .as_ref()
                .and_then(|p| p.identity_file.as_ref().and_then(|v| v.first().cloned()))
                .map(expand_tilde)
                .unwrap_or_else(default_key_path);
            AuthMethod::KeyFile(key_path)
        }
    };

    Ok(ConnectParams {
        alias: if host_str != host {
            Some(host_str.to_string())
        } else {
            None
        },
        user,
        host,
        ssh_port,
        auth: resolved_auth,
        check_host_key: !no_host_key_check,
    })
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
pub(crate) struct TunnelEntry {
    remote_host: String,
    remote_port: u32,
    /// 当前活动的转发连接数
    connections: Arc<AtomicUsize>,
    /// 累计转发字节：rx=远端→本地，tx=本地→远端
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    /// 监听循环任务；abort 即释放本地端口；None 表示已停用
    task: Option<JoinHandle<()>>,
    /// 该隧道的事件日志
    log: TunnelLog,
}

/// 向外部（CLI/TUI）暴露的隧道快照
#[derive(Clone)]
pub(crate) struct TunnelInfo {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u32,
    pub enabled: bool,
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

/// 单个主机的隧道管理器：持有该主机的 SSH 连接句柄与所属隧道表
pub(crate) struct TunnelManager {
    pub params: ConnectParams,
    pub handle: Arc<RwLock<Option<Handle<SshHandler>>>>,
    pub tunnels: HashMap<u16, TunnelEntry>,
    pub status: Arc<std::sync::Mutex<ConnectionStatus>>,
    /// 速率计算的上一采样点
    last_rx: HashMap<u16, u64>,
    last_tx: HashMap<u16, u64>,
    last_sample: Instant,
    /// 上次 keepalive 探测时间（闲置时维持连接活性并检测半开断链）
    last_keepalive: Instant,
}

/// 单个转发连接的中继
async fn relay(
    session: Arc<RwLock<Option<Handle<SshHandler>>>>,
    mut stream: TcpStream,
    remote_host: &str,
    remote_port: u32,
    originator_host: &str,
    originator_port: u32,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = {
        let handle_guard = session.read().await;
        let Some(handle) = handle_guard.as_ref() else {
            return Err("SSH 会话未连接或已断开".into());
        };
        handle
            .channel_open_direct_tcpip(remote_host, remote_port, originator_host, originator_port)
            .await?
    };
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

/// 隧道监听循环
async fn listen_loop(
    listener: TcpListener,
    handle: Arc<RwLock<Option<Handle<SshHandler>>>>,
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
            let result = relay(
                handle, stream, &host, port, &peer_addr, peer_port, rx_bytes, tx_bytes,
            )
            .await;
            connections.fetch_sub(1, Ordering::SeqCst);
            match result {
                Ok(()) => log_push(&log, format!("{peer} 连接结束")),
                Err(e) => log_push(&log, format!("{peer} 转发失败：{e}")),
            }
        });
    }
}

impl TunnelManager {
    /// 建立 SSH 主连接（支持公钥认证与密码认证）
    async fn connect_handle(params: &ConnectParams) -> Result<Handle<SshHandler>, String> {
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

        let auth_res = match &params.auth {
            AuthMethod::KeyFile(key_path) => {
                let key = load_secret_key(key_path, None)
                    .map_err(|e| format!("加载私钥 {} 失败：{e}", key_path.display()))?;
                let key = Arc::new(key);
                let rsa_hash = session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| format!("获取服务器 RSA 算法失败：{e}"))?
                    .flatten();
                session
                    .authenticate_publickey(
                        &params.user,
                        PrivateKeyWithHashAlg::new(key, rsa_hash),
                    )
                    .await
                    .map_err(|e| format!("SSH 公钥认证请求失败：{e}"))?
            }
            AuthMethod::Password(password) => {
                session
                    .authenticate_password(&params.user, password)
                    .await
                    .map_err(|e| format!("SSH 密码认证请求失败：{e}"))?
            }
        };

        if !auth_res.success() {
            let method_name = match &params.auth {
                AuthMethod::KeyFile(_) => "公钥",
                AuthMethod::Password(_) => "密码",
            };
            return Err(format!(
                "SSH {method_name}认证失败（{}@{}）",
                params.user, params.host
            ));
        }
        Ok(session)
    }

    /// 建立 SSH 主连接并初始化管理器
    pub(crate) async fn connect(
        params: ConnectParams,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let handle = Self::connect_handle(&params)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        Ok(Self {
            params,
            handle: Arc::new(RwLock::new(Some(handle))),
            tunnels: HashMap::new(),
            status: Arc::new(std::sync::Mutex::new(ConnectionStatus::Connected)),
            last_rx: HashMap::new(),
            last_tx: HashMap::new(),
            last_sample: Instant::now(),
            last_keepalive: Instant::now(),
        })
    }

    /// 创建一个初始未连接的管理器（用于加载持久化配置，后续自动重连）
    pub(crate) fn new_disconnected(params: ConnectParams) -> Self {
        Self {
            params,
            handle: Arc::new(RwLock::new(None)),
            tunnels: HashMap::new(),
            status: Arc::new(std::sync::Mutex::new(ConnectionStatus::Disconnected)),
            last_rx: HashMap::new(),
            last_tx: HashMap::new(),
            last_sample: Instant::now(),
            // 设定为 30 秒前，让第一次 check_and_reconnect 立即尝试重连
            last_keepalive: Instant::now()
                .checked_sub(Duration::from_secs(30))
                .unwrap_or_else(Instant::now),
        }
    }

    /// 恢复一条停用状态的隧道（不绑定本地端口，仅保留配置）
    pub(crate) fn restore_disabled(
        &mut self,
        local_port: u16,
        remote_host: &str,
        remote_port: u32,
    ) {
        let connections = Arc::new(AtomicUsize::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let log: TunnelLog = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        log_push(
            &log,
            format!("隧道已加载（停用状态）：{local_port} -> {remote_host}:{remote_port}"),
        );
        self.tunnels.insert(
            local_port,
            TunnelEntry {
                remote_host: remote_host.to_string(),
                remote_port,
                connections,
                rx_bytes,
                tx_bytes,
                task: None,
                log,
            },
        );
    }

    pub(crate) fn status(&self) -> ConnectionStatus {
        *self.status.lock().unwrap()
    }

    /// 检测 SSH 主连接是否断开；若断开则启动后台重连任务
    pub(crate) async fn check_and_reconnect(&mut self) -> ConnectionStatus {
        let now = self.status();
        if matches!(now, ConnectionStatus::Reconnecting(_)) {
            return now;
        }
        let need_probe = self.last_keepalive.elapsed() >= Duration::from_secs(30);
        if need_probe {
            self.last_keepalive = Instant::now();
        }
        let closed = {
            let handle_guard = self.handle.read().await;
            if let Some(handle) = handle_guard.as_ref() {
                if handle.is_closed() {
                    true
                } else if need_probe {
                    matches!(
                        tokio::time::timeout(Duration::from_secs(10), handle.send_ping()).await,
                        Err(_) | Ok(Err(_))
                    )
                } else {
                    false
                }
            } else {
                need_probe
            }
        };
        if !closed {
            return now;
        }
        *self.status.lock().unwrap() = ConnectionStatus::Reconnecting(0);
        let params = self.params.clone();
        let handle = Arc::clone(&self.handle);
        let status = Arc::clone(&self.status);
        tokio::spawn(async move {
            for attempt in 1..=5 {
                *status.lock().unwrap() = ConnectionStatus::Reconnecting(attempt);
                match TunnelManager::connect_handle(&params).await {
                    Ok(new_handle) => {
                        *handle.write().await = Some(new_handle);
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

    /// 新增一条隧道
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
        log_push(
            &log,
            format!("隧道已创建：{local_port} -> {remote_host}:{remote_port}"),
        );
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
                task: Some(task),
                log,
            },
        );
        Ok(())
    }

    /// 停止并删除一条隧道
    pub(crate) async fn remove(&mut self, local_port: u16) -> Result<(), String> {
        let entry = self
            .tunnels
            .remove(&local_port)
            .ok_or_else(|| format!("隧道 {local_port} 不存在"))?;
        if let Some(task) = entry.task {
            task.abort();
        }
        Ok(())
    }

    /// 停用一条隧道（释放本地监听端口并中断后续连入）
    pub(crate) async fn disable(&mut self, local_port: u16) -> Result<(), String> {
        let entry = self
            .tunnels
            .get_mut(&local_port)
            .ok_or_else(|| format!("隧道 {local_port} 不存在"))?;
        if let Some(task) = entry.task.take() {
            task.abort();
            entry.connections.store(0, Ordering::SeqCst);
            log_push(
                &entry.log,
                format!(
                    "隧道已停用：{local_port} -> {}:{}",
                    entry.remote_host, entry.remote_port
                ),
            );
            Ok(())
        } else {
            Err(format!("隧道 {local_port} 已经是停用状态"))
        }
    }

    /// 启用一条已停用的隧道（重新绑定本地监听端口并恢复流量转发）
    pub(crate) async fn enable(&mut self, local_port: u16) -> Result<(), String> {
        let entry = self
            .tunnels
            .get_mut(&local_port)
            .ok_or_else(|| format!("隧道 {local_port} 不存在"))?;
        if entry.task.is_some() {
            return Err(format!("隧道 {local_port} 已经在运行中"));
        }
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|e| format!("本地端口 {local_port} 绑定失败：{e}"))?;
        let task = tokio::spawn(listen_loop(
            listener,
            Arc::clone(&self.handle),
            entry.remote_host.clone(),
            entry.remote_port,
            Arc::clone(&entry.connections),
            Arc::clone(&entry.rx_bytes),
            Arc::clone(&entry.tx_bytes),
            Arc::clone(&entry.log),
        ));
        entry.task = Some(task);
        log_push(
            &entry.log,
            format!(
                "隧道已启用：{local_port} -> {}:{}",
                entry.remote_host, entry.remote_port
            ),
        );
        Ok(())
    }

    /// 当前所有隧道快照（含实时速率与运行状态）
    pub(crate) fn list(&mut self) -> Vec<TunnelInfo> {
        let now = Instant::now();
        let dt = now
            .duration_since(self.last_sample)
            .as_secs_f64()
            .max(0.001);
        let mut v: Vec<TunnelInfo> = self
            .tunnels
            .iter()
            .map(|(&local_port, e)| {
                let rx = e.rx_bytes.load(Ordering::SeqCst);
                let tx = e.tx_bytes.load(Ordering::SeqCst);
                let rx_prev = self.last_rx.get(&local_port).copied().unwrap_or(0);
                let tx_prev = self.last_tx.get(&local_port).copied().unwrap_or(0);
                let is_running = e.task.is_some();
                let rx_rate = if is_running {
                    ((rx.saturating_sub(rx_prev)) as f64 / dt) as u64
                } else {
                    0
                };
                let tx_rate = if is_running {
                    ((tx.saturating_sub(tx_prev)) as f64 / dt) as u64
                } else {
                    0
                };
                self.last_rx.insert(local_port, rx);
                self.last_tx.insert(local_port, tx);
                TunnelInfo {
                    local_port,
                    remote_host: e.remote_host.clone(),
                    remote_port: e.remote_port,
                    enabled: is_running,
                    connections: if is_running {
                        e.connections.load(Ordering::SeqCst)
                    } else {
                        0
                    },
                    rx_bytes: rx,
                    tx_bytes: tx,
                    rx_rate,
                    tx_rate,
                    log: e
                        .log
                        .lock()
                        .map(|l| l.iter().cloned().collect())
                        .unwrap_or_default(),
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
            if let Some(task) = entry.task {
                task.abort();
            }
        }
        if let Some(handle) = self.handle.write().await.take() {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "English")
                .await;
        }
    }
}

/// 单个主机的状态概要
#[derive(Clone)]
pub(crate) struct HostSummary {
    pub id: String,
    pub display_name: String,
    pub params: ConnectParams,
    pub status: ConnectionStatus,
    pub tunnels: Vec<TunnelInfo>,
    pub total_rx_rate: u64,
    pub total_tx_rate: u64,
}

/// 多主机隧道总管理器
pub(crate) struct MultiTunnelManager {
    sessions: Vec<TunnelManager>,
    config_path: PathBuf,
}

impl MultiTunnelManager {
    pub(crate) fn new(config_path: PathBuf) -> Self {
        Self {
            sessions: Vec::new(),
            config_path,
        }
    }

    pub(crate) fn has_session(&self, display_name: &str) -> bool {
        self.sessions
            .iter()
            .any(|s| s.params.display_name() == display_name)
    }

    pub(crate) fn to_config(&self) -> AppConfig {
        let mut hosts = Vec::new();
        for s in &self.sessions {
            let mut tunnels = Vec::new();
            for (&port, entry) in &s.tunnels {
                tunnels.push(SavedTunnel {
                    local_port: port,
                    remote_host: entry.remote_host.clone(),
                    remote_port: entry.remote_port,
                    enabled: entry.task.is_some(),
                });
            }
            tunnels.sort_by_key(|t| t.local_port);
            hosts.push(SavedHost {
                params: s.params.clone(),
                tunnels,
            });
        }
        AppConfig { hosts }
    }

    pub(crate) fn save_config(&self) {
        let cfg = self.to_config();
        if let Err(e) = save_config(&cfg, &self.config_path) {
            eprintln!("[警告] 保存配置至 {} 失败：{e}", self.config_path.display());
        }
    }

    pub(crate) async fn restore_session(&mut self, saved: SavedHost) {
        let id = saved.params.display_name();
        if self.has_session(&id) {
            return;
        }
        let mut mgr = match TunnelManager::connect(saved.params.clone()).await {
            Ok(m) => m,
            Err(_) => {
                TunnelManager::new_disconnected(saved.params.clone())
            }
        };
        for t in saved.tunnels {
            if t.enabled {
                if let Err(e) = mgr.add(t.local_port, &t.remote_host, t.remote_port).await {
                    mgr.restore_disabled(t.local_port, &t.remote_host, t.remote_port);
                    if let Some(entry) = mgr.tunnels.get_mut(&t.local_port) {
                        log_push(&entry.log, format!("启动监听失败：{e}，已设为停用状态"));
                    }
                }
            } else {
                mgr.restore_disabled(t.local_port, &t.remote_host, t.remote_port);
            }
        }
        self.sessions.push(mgr);
    }

    pub(crate) async fn add_session(&mut self, params: ConnectParams) -> Result<(), String> {
        let id = params.display_name();
        if self.has_session(&id) {
            return Err(format!("主机 [{id}] 已经连接，请勿重复连接"));
        }
        let mgr = TunnelManager::connect(params)
            .await
            .map_err(|e| e.to_string())?;
        self.sessions.push(mgr);
        self.save_config();
        Ok(())
    }

    pub(crate) async fn remove_session(&mut self, session_id: &str) -> Result<(), String> {
        if let Some(pos) = self
            .sessions
            .iter()
            .position(|s| s.params.display_name() == session_id)
        {
            let mut mgr = self.sessions.remove(pos);
            mgr.shutdown().await;
            self.save_config();
            Ok(())
        } else {
            Err(format!("主机 [{session_id}] 未找到"))
        }
    }

    pub(crate) async fn add_tunnel(
        &mut self,
        session_id: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u32,
    ) -> Result<(), String> {
        // 全局检查本地端口占用
        for s in &self.sessions {
            if s.tunnels.contains_key(&local_port) {
                return Err(format!(
                    "本地端口 {local_port} 已被主机 [{}] 的隧道占用",
                    s.params.display_name()
                ));
            }
        }
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.params.display_name() == session_id)
            .ok_or_else(|| format!("主机 [{session_id}] 未连接"))?;
        let res = session.add(local_port, remote_host, remote_port).await;
        if res.is_ok() {
            self.save_config();
        }
        res
    }

    pub(crate) async fn remove_tunnel(
        &mut self,
        session_id: &str,
        local_port: u16,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.params.display_name() == session_id)
            .ok_or_else(|| format!("主机 [{session_id}] 未连接"))?;
        let res = session.remove(local_port).await;
        if res.is_ok() {
            self.save_config();
        }
        res
    }

    pub(crate) async fn enable_tunnel(
        &mut self,
        session_id: &str,
        local_port: u16,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.params.display_name() == session_id)
            .ok_or_else(|| format!("主机 [{session_id}] 未连接"))?;
        let res = session.enable(local_port).await;
        if res.is_ok() {
            self.save_config();
        }
        res
    }

    pub(crate) async fn disable_tunnel(
        &mut self,
        session_id: &str,
        local_port: u16,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.params.display_name() == session_id)
            .ok_or_else(|| format!("主机 [{session_id}] 未连接"))?;
        let res = session.disable(local_port).await;
        if res.is_ok() {
            self.save_config();
        }
        res
    }

    pub(crate) async fn scan_ports(&self, session_id: &str) -> Vec<RemotePort> {
        if let Some(s) = self
            .sessions
            .iter()
            .find(|s| s.params.display_name() == session_id)
        {
            scan_remote_ports(&s.handle).await
        } else {
            Vec::new()
        }
    }

    pub(crate) async fn tick_and_summarize(&mut self) -> Vec<HostSummary> {
        let mut summaries = Vec::new();
        for session in &mut self.sessions {
            let status = session.check_and_reconnect().await;
            let tunnels = session.list();
            let total_rx_rate: u64 = tunnels.iter().map(|t| t.rx_rate).sum();
            let total_tx_rate: u64 = tunnels.iter().map(|t| t.tx_rate).sum();
            summaries.push(HostSummary {
                id: session.params.display_name(),
                display_name: session.params.display_name(),
                params: session.params.clone(),
                status,
                tunnels,
                total_rx_rate,
                total_tx_rate,
            });
        }
        summaries
    }

    pub(crate) async fn shutdown_all(&mut self) {
        self.save_config();
        for mut s in self.sessions.drain(..) {
            s.shutdown().await;
        }
    }
}

impl Default for MultiTunnelManager {
    fn default() -> Self {
        Self::new(default_config_path())
    }
}

// ---------- 后台管理任务（TUI 协作层） ----------

/// 前台（TUI）发往管理任务的控制指令
pub(crate) enum Command {
    ConnectHost {
        params: ConnectParams,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    DisconnectHost {
        session_id: String,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    AddTunnel {
        session_id: String,
        local_port: u16,
        remote_host: String,
        remote_port: u32,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    RemoveTunnel {
        session_id: String,
        local_port: u16,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    EnableTunnel {
        session_id: String,
        local_port: u16,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    DisableTunnel {
        session_id: String,
        local_port: u16,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    ScanPorts {
        session_id: String,
        reply: tokio::sync::oneshot::Sender<Vec<RemotePort>>,
    },
    Quit,
}

/// 管理任务推送给前台的状态事件
pub(crate) enum Event {
    State { hosts: Vec<HostSummary> },
}

/// 管理任务主循环
pub(crate) async fn manager_loop(
    mut mgr: MultiTunnelManager,
    mut rx: tokio::sync::mpsc::Receiver<Command>,
    events: tokio::sync::mpsc::UnboundedSender<Event>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let hosts = mgr.tick_and_summarize().await;
                let _ = events.send(Event::State { hosts });
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Command::ConnectHost { params, reply } => {
                        let r = mgr.add_session(params).await;
                        let _ = reply.send(r);
                    }
                    Command::DisconnectHost { session_id, reply } => {
                        let r = mgr.remove_session(&session_id).await;
                        let _ = reply.send(r);
                    }
                    Command::AddTunnel { session_id, local_port, remote_host, remote_port, reply } => {
                        let r = mgr.add_tunnel(&session_id, local_port, &remote_host, remote_port).await;
                        let _ = reply.send(r);
                    }
                    Command::RemoveTunnel { session_id, local_port, reply } => {
                        let r = mgr.remove_tunnel(&session_id, local_port).await;
                        let _ = reply.send(r);
                    }
                    Command::EnableTunnel { session_id, local_port, reply } => {
                        let r = mgr.enable_tunnel(&session_id, local_port).await;
                        let _ = reply.send(r);
                    }
                    Command::DisableTunnel { session_id, local_port, reply } => {
                        let r = mgr.disable_tunnel(&session_id, local_port).await;
                        let _ = reply.send(r);
                    }
                    Command::ScanPorts { session_id, reply } => {
                        let ports = mgr.scan_ports(&session_id).await;
                        let _ = reply.send(ports);
                    }
                    Command::Quit => break,
                }
                let hosts = mgr.tick_and_summarize().await;
                let _ = events.send(Event::State { hosts });
            }
        }
    }
    mgr.shutdown_all().await;
}

// ---------- 远端端口发现 ----------

/// 在远端执行 `ss -tln`（fallback: netstat -tln），解析监听端口列表。
pub(crate) async fn scan_remote_ports(
    handle: &RwLock<Option<Handle<SshHandler>>>,
) -> Vec<RemotePort> {
    let mut channel = {
        let h_guard = handle.read().await;
        let Some(h) = h_guard.as_ref() else {
            return Vec::new();
        };
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
        let process = extract_process(line);
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
    if let Some(idx) = line.find("((\"") {
        let rest = &line[idx + 3..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    if let Some(idx) = line.find("LISTEN") {
        let tail = line[idx + 6..].trim();
        if let Some(slash) = tail.find('/') {
            let name: String = tail[slash + 1..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
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
        assert_eq!(
            ports[0],
            RemotePort {
                port: 22,
                process: "sshd".into()
            }
        );
        assert_eq!(
            ports[1],
            RemotePort {
                port: 8000,
                process: "python3".into()
            }
        );
        assert_eq!(
            ports[2],
            RemotePort {
                port: 8848,
                process: "python3".into()
            }
        );
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
        assert_eq!(
            ports[0],
            RemotePort {
                port: 22,
                process: "sshd".into()
            }
        );
        assert_eq!(
            ports[1],
            RemotePort {
                port: 631,
                process: "cupsd".into()
            }
        );
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

    #[test]
    fn test_resolve_target_str() {
        let res = resolve_target_str("ubuntu@1.2.3.4:2222", None, 22, false).unwrap();
        assert_eq!(res.user, "ubuntu");
        assert_eq!(res.host, "1.2.3.4");
        assert_eq!(res.ssh_port, 2222);

        let res2 = resolve_target_str("root@10.0.0.1", Some(AuthMethod::Password("secret".into())), 22, false).unwrap();
        assert_eq!(res2.user, "root");
        assert_eq!(res2.host, "10.0.0.1");
        assert_eq!(res2.ssh_port, 22);
        assert_eq!(res2.auth, AuthMethod::Password("secret".into()));
    }

    #[test]
    fn test_tunnel_info_enabled_state() {
        let mut info = TunnelInfo {
            local_port: 8080,
            remote_host: "127.0.0.1".into(),
            remote_port: 80,
            enabled: true,
            connections: 2,
            rx_bytes: 1024,
            tx_bytes: 2048,
            rx_rate: 100,
            tx_rate: 200,
            log: vec!["created".into()],
        };
        assert!(info.enabled);
        info.enabled = false;
        assert!(!info.enabled);
    }

    #[test]
    fn test_config_save_and_load() {
        let tmp_dir = std::env::temp_dir().join(format!("mtui_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let config_path = tmp_dir.join("test_config.json");

        let cfg = AppConfig {
            hosts: vec![
                SavedHost {
                    params: ConnectParams {
                        alias: Some("prod-web".into()),
                        user: "deploy".into(),
                        host: "192.168.1.100".into(),
                        ssh_port: 22,
                        auth: AuthMethod::KeyFile(PathBuf::from("/home/user/.ssh/id_rsa")),
                        check_host_key: true,
                    },
                    tunnels: vec![
                        SavedTunnel {
                            local_port: 8080,
                            remote_host: "127.0.0.1".into(),
                            remote_port: 80,
                            enabled: true,
                        },
                        SavedTunnel {
                            local_port: 3306,
                            remote_host: "127.0.0.1".into(),
                            remote_port: 3306,
                            enabled: false,
                        },
                    ],
                },
                SavedHost {
                    params: ConnectParams {
                        alias: None,
                        user: "root".into(),
                        host: "10.0.0.5".into(),
                        ssh_port: 2222,
                        auth: AuthMethod::Password("mypassword".into()),
                        check_host_key: false,
                    },
                    tunnels: vec![SavedTunnel {
                        local_port: 5432,
                        remote_host: "127.0.0.1".into(),
                        remote_port: 5432,
                        enabled: true,
                    }],
                },
            ],
        };

        // 保存配置
        save_config(&cfg, &config_path).expect("save_config should succeed");
        assert!(config_path.exists());

        // 读取配置
        let loaded = load_config(&config_path);
        assert_eq!(loaded.hosts.len(), 2);
        assert_eq!(loaded.hosts[0].params.alias.as_deref(), Some("prod-web"));
        assert_eq!(loaded.hosts[0].tunnels.len(), 2);
        assert!(loaded.hosts[0].tunnels[0].enabled);
        assert!(!loaded.hosts[0].tunnels[1].enabled);

        assert_eq!(loaded.hosts[1].params.display_name(), "root@10.0.0.5:2222");
        assert_eq!(
            loaded.hosts[1].params.auth,
            AuthMethod::Password("mypassword".into())
        );
        assert_eq!(loaded.hosts[1].tunnels.len(), 1);
        assert!(loaded.hosts[1].tunnels[0].enabled);

        // 清理临时文件
        let _ = std::fs::remove_dir_all(tmp_dir);
    }
}
