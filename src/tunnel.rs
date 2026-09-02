//! 隧道控制中心：维护一条 SSH 主连接，管理多个本地端口监听的动态启停。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use russh::client::{self, Handle};
use russh::keys::known_hosts::check_known_hosts;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// SSH 会话事件处理器：负责服务器主机密钥校验（防中间人攻击）
#[derive(Clone)]
pub(crate) struct SshHandler {
    host: String,
    port: u16,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
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

/// 单条隧道（本地端口监听）的运行时状态
struct TunnelEntry {
    remote_host: String,
    remote_port: u32,
    /// 当前活动的转发连接数（供 list 展示）
    connections: Arc<AtomicUsize>,
    /// 监听循环任务；abort 即释放本地端口
    task: JoinHandle<()>,
}

/// 向外部（CLI/TUI）暴露的隧道快照
pub(crate) struct TunnelInfo {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u32,
    pub connections: usize,
}

/// 隧道控制中心：持有 SSH 主连接句柄 + 隧道表
pub(crate) struct TunnelManager {
    handle: Arc<Mutex<Handle<SshHandler>>>,
    tunnels: HashMap<u16, TunnelEntry>,
}

/// 单个转发连接的中继：申请一条 direct-tcpip 通道并双向转发，直到任一端关闭。
async fn relay(
    handle: &Handle<SshHandler>,
    mut stream: TcpStream,
    remote_host: &str,
    remote_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut channel = handle
        .channel_open_direct_tcpip(remote_host, remote_port, originator_host, originator_port)
        .await?;

    let mut stream_closed = false;
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = stream.read(&mut buf), if !stream_closed => {
                match r {
                    Ok(0) => {
                        stream_closed = true;
                        channel.eof().await?;
                    }
                    Ok(n) => channel.data(&buf[..n]).await?,
                    Err(e) => return Err(e.into()),
                }
            }
            Some(msg) = channel.wait() => {
                match msg {
                    ChannelMsg::Data { data } => {
                        stream.write_all(&data).await?;
                    }
                    ChannelMsg::Eof => {
                        if !stream_closed {
                            channel.eof().await?;
                        }
                        break;
                    }
                    _ => {} // 忽略 WindowAdjusted 等消息
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
        let (host, port) = (remote_host.clone(), remote_port);
        let peer_addr = peer.ip().to_string();
        let peer_port = peer.port().into();
        tokio::spawn(async move {
            connections.fetch_add(1, Ordering::SeqCst);
            // 锁仅在申请通道期间持有，中继过程不占用 session
            let handle = handle.lock().await;
            let result = relay(&handle, stream, &host, port, &peer_addr, peer_port).await;
            connections.fetch_sub(1, Ordering::SeqCst);
            if let Err(e) = result {
                eprintln!("[-] 隧道 {local_port} {peer} 转发失败：{e}");
            }
        });
    }
}

impl TunnelManager {
    /// 建立 SSH 主连接
    pub(crate) async fn connect(
        user: &str,
        host: &str,
        ssh_port: u16,
        key_path: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key = load_secret_key(key_path, None)
            .map_err(|e| format!("加载私钥 {} 失败：{e}", key_path.display()))?;
        let key = Arc::new(key);

        let config = Arc::new(client::Config::default());
        let mut session = client::connect(
            config,
            (host, ssh_port),
            SshHandler {
                host: host.to_string(),
                port: ssh_port,
            },
        )
        .await?;
        let auth = session
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(key, session.best_supported_rsa_hash().await?.flatten()),
            )
            .await?;
        if !auth.success() {
            return Err(format!("SSH 公钥认证失败（{user}@{host}）").into());
        }
        Ok(Self {
            handle: Arc::new(Mutex::new(session)),
            tunnels: HashMap::new(),
        })
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
        let task = tokio::spawn(listen_loop(
            listener,
            Arc::clone(&self.handle),
            local_port,
            remote_host.to_string(),
            remote_port,
            Arc::clone(&connections),
        ));
        self.tunnels.insert(
            local_port,
            TunnelEntry {
                remote_host: remote_host.to_string(),
                remote_port,
                connections,
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

    /// 当前所有隧道快照
    pub(crate) fn list(&self) -> Vec<TunnelInfo> {
        let mut v: Vec<TunnelInfo> = self
            .tunnels
            .iter()
            .map(|(&local_port, e)| TunnelInfo {
                local_port,
                remote_host: e.remote_host.clone(),
                remote_port: e.remote_port,
                connections: e.connections.load(Ordering::SeqCst),
            })
            .collect();
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