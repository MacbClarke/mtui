//! mtui — 动态 SSH 隧道工具
//!
//! Step 3：Ratatui TUI 界面。架构：
//!   TUI 前台（app.rs）──mpsc 指令/快照──► 管理任务（tunnel.rs）
//!   管理任务持有 SSH 主连接 + 隧道表，TUI 只做渲染与键盘事件。

mod app;
mod tunnel;

use std::path::PathBuf;

use clap::Parser;
use tokio::sync::mpsc;
use tunnel::{manager_loop, TunnelManager};

/// mtui — 动态 SSH 隧道工具
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// SSH 服务器，格式 user@host
    #[arg(value_name = "USER@HOST")]
    target: String,

    /// SSH 服务器端口
    #[arg(short = 'p', long, default_value_t = 22)]
    ssh_port: u16,

    /// 私钥路径（默认 ~/.ssh/id_ed25519）
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,
}

fn default_key_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".ssh/id_ed25519")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let (user, host) = args
        .target
        .split_once('@')
        .ok_or("目标格式应为 user@host，例如 root@example.com")?;

    // 1. 建立 SSH 主连接（失败直接退出，不进 TUI）
    let key_path = args.key.clone().unwrap_or_else(default_key_path);
    let mgr = TunnelManager::connect(user, host, args.ssh_port, &key_path).await?;

    // 2. 前后台解耦：管理任务持有 TunnelManager，TUI 通过通道交互
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(manager_loop(mgr, cmd_rx, event_tx));

    // 3. TUI 主循环（退出时向管理任务发送 Quit）
    app::run(cmd_tx, event_rx).await?;
    Ok(())
}