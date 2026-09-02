//! 测试用 SSH 服务端：接受任意公钥/密码认证，将 direct-tcpip 转发到目标。
//! 用法：cargo run --example fake_sshd -- [监听端口] [主机密钥路径]
//! 用于验证 mtui 的断线检测与自动重连：杀掉本进程 → mtui 进入重连等待；
//! 重新启动 → mtui 自动恢复隧道。

use std::path::PathBuf;
use std::sync::Arc;

use russh::keys::load_secret_key;
use russh::server::{self, ChannelOpenHandle, Msg};
use russh::{Channel, ChannelMsg, ChannelOpenFailure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone)]
struct FakeSshd;

impl server::Server for FakeSshd {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Self
    }

    fn handle_session_error(&mut self, _error: <Self::Handler as server::Handler>::Error) {
        eprintln!("[fake_sshd] session error");
    }
}

impl server::Handler for FakeSshd {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        match TcpStream::connect((host_to_connect.to_string(), port_to_connect as u16)).await {
            Ok(stream) => {
                reply.accept().await;
                tokio::spawn(pipe(channel, stream));
            }
            Err(e) => {
                eprintln!("[fake_sshd] 无法连接转发目标 {host_to_connect}:{port_to_connect}：{e}");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

/// 双向中继：TcpStream <-> SSH channel
async fn pipe(mut channel: Channel<Msg>, mut stream: TcpStream) {
    let mut stream_closed = false;
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = stream.read(&mut buf), if !stream_closed => {
                match r {
                    Ok(0) => {
                        stream_closed = true;
                        let _ = channel.eof().await;
                    }
                    Ok(n) => {
                        if channel.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Some(msg) = channel.wait() => {
                match msg {
                    ChannelMsg::Data { data } => {
                        if stream.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    ChannelMsg::Eof => break,
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u16 = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("端口参数无效"))
        .unwrap_or(2222);
    let key_path = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".ssh/id_ed25519")
        });

    let key = load_secret_key(&key_path, None)?;
    let config = Arc::new(server::Config {
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    println!("[fake_sshd] 监听 127.0.0.1:{port}");

    loop {
        let (stream, _) = listener.accept().await?;
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _ = server::run_stream(config, stream, FakeSshd).await;
        });
    }
}