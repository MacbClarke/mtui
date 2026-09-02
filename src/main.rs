//! mtui — 动态 SSH 隧道工具
//!
//! Step 4：~/.ssh/config 别名支持、实时速率统计、断线自动重连。

mod app;
mod tunnel;

use std::path::PathBuf;

use clap::Parser;
use ssh2_config::{ParseRule, SshConfig};
use tokio::sync::mpsc;
use tunnel::{manager_loop, ConnectParams, TunnelManager};

/// mtui — 动态 SSH 隧道工具
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// SSH 目标：user@host 直接连接；别名从 ~/.ssh/config 解析
    #[arg(value_name = "USER@HOST|ALIAS")]
    target: String,

    /// SSH 服务器端口（被 config 中 Port 覆盖则不生效）
    #[arg(short = 'p', long, default_value_t = 22)]
    ssh_port: u16,

    /// 私钥路径（默认 ~/.ssh/id_ed25519，config 中 IdentityFile 可覆盖）
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,

    /// 跳过 known_hosts 校验（不安全，仅测试/内网）
    #[arg(long)]
    no_host_key_check: bool,
}

fn default_key_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".ssh/id_ed25519")
}

/// 解析目标：user@host 或别名（含 user@alias）。返回 (user, host, port, key)
fn resolve_target(args: &Args) -> Result<(String, String, u16, PathBuf), String> {
    let (explicit_user, rest) = match args.target.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, args.target.as_str()),
    };

    // 尝试从 ~/.ssh/config 解析别名
    let mut from_config = None;
    let config_path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".ssh/config"));
    if let Some(path) = &config_path {
        if let Ok(f) = std::fs::File::open(path) {
            let mut reader = std::io::BufReader::new(f);
            if let Ok(cfg) = SshConfig::default()
                .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS)
            {
                from_config = Some(cfg.query(rest));
            }
        }
    }

    let host = from_config
        .as_ref()
        .and_then(|p| p.host_name.clone())
        .unwrap_or_else(|| rest.to_string());
    let user = explicit_user
        .map(str::to_string)
        .or_else(|| from_config.as_ref().and_then(|p| p.user.clone()))
        .ok_or_else(|| {
            format!(
                "无法确定用户名：目标 '{rest}' 请使用 user@host 格式，或在 ~/.ssh/config 中配置 User"
            )
        })?;
    let port = from_config
        .as_ref()
        .and_then(|p| p.port)
        .unwrap_or(args.ssh_port);
    let key = from_config
        .as_ref()
        .and_then(|p| p.identity_file.as_ref().and_then(|v| v.first().cloned()))
        .or_else(|| args.key.clone())
        .unwrap_or_else(default_key_path);
    Ok((user, host, port, key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let (user, host, ssh_port, key_path) = resolve_target(&args)?;
    println!("[OK] 正在连接 {user}@{host}:{ssh_port} …");
    let params = ConnectParams {
        user,
        host,
        ssh_port,
        key_path,
        check_host_key: !args.no_host_key_check,
    };

    // 1. 建立 SSH 主连接（失败直接退出，不进 TUI）
    let mgr = TunnelManager::connect(params).await?;

    // 2. 前后台解耦：管理任务持有 TunnelManager，TUI 通过通道交互
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(manager_loop(mgr, cmd_rx, event_tx));

    // 3. TUI 主循环（退出时向管理任务发送 Quit）
    app::run(cmd_tx, event_rx).await?;
    Ok(())
}