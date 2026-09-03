//! mtui — 动态 SSH 隧道管理工具（多主机版）

mod app;
mod tunnel;

use std::path::PathBuf;

use clap::Parser;
use tokio::sync::mpsc;
use tunnel::{
    default_config_path, load_config, manager_loop, resolve_target_str, AuthMethod,
    MultiTunnelManager,
};

/// mtui — 动态 SSH 隧道与端口转发管理工具
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// 可选：初始 SSH 目标（user@host 或 ~/.ssh/config 别名），留空直接进入主机管理
    #[arg(value_name = "USER@HOST|ALIAS")]
    target: Option<String>,

    /// SSH 服务器端口
    #[arg(short = 'p', long, default_value_t = 22)]
    ssh_port: u16,

    /// 私钥路径（默认 ~/.ssh/id_ed25519）
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,

    /// SSH 登录密码（指定后优先使用密码认证）
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// 跳过 known_hosts 校验（仅测试/内网）
    #[arg(long)]
    no_host_key_check: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let initial_params = match args.target {
        Some(ref t) => {
            let auth = if let Some(pwd) = args.password {
                Some(AuthMethod::Password(pwd))
            } else {
                args.key.map(AuthMethod::KeyFile)
            };
            match resolve_target_str(t, auth, args.ssh_port, args.no_host_key_check) {
                Ok(p) => Some(p),
                Err(e) => {
                    eprintln!("[错误] 目标解析失败：{e}");
                    return Err(e.into());
                }
            }
        }
        None => None,
    };

    let config_path = default_config_path();
    let saved_config = load_config(&config_path);

    let mut mgr = MultiTunnelManager::new(config_path);

    // 1. 静默恢复之前保存的主机及隧道配置（界面直接呈现）
    for saved in saved_config.hosts {
        mgr.restore_session(saved).await;
    }

    // 2. 如果命令行传入了初始目标，且尚未添加，则连接初始目标
    if let Some(params) = initial_params {
        let name = params.display_name();
        if !mgr.has_session(&name) {
            let _ = mgr.add_session(params).await;
        }
    }

    // 前后台解耦：管理任务持有 MultiTunnelManager，TUI 通过通道交互
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(manager_loop(mgr, cmd_rx, event_tx));

    // 启动 TUI
    app::run(cmd_tx, event_rx).await?;
    Ok(())
}
