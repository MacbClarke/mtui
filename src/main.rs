//! mtui — 动态 SSH 隧道工具
//!
//! Step 2：TunnelManager 动态生命周期管理。
//! 交互命令：add <本地端口> <远端 host:port> / rm <端口> / ls / quit

mod tunnel;

use std::io::{stdin, stdout, Write};
use std::path::PathBuf;

use clap::Parser;
use tunnel::TunnelManager;

/// mtui — 动态 SSH 隧道工具（Step 2：隧道动态增删）
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

fn print_help() {
    println!(
        "命令：\n  \
         add <本地端口> <远端host:port>   新增隧道\n  \
         rm  <本地端口>                   停止隧道\n  \
         ls                               列出隧道\n  \
         quit                             退出"
    );
}

/// 交互命令循环
async fn repl(mgr: &mut TunnelManager) {
    let mut line = String::new();
    loop {
        print!("mtui> ");
        if stdout().flush().is_err() {
            break;
        }
        match stdin().read_line(&mut line) {
            Ok(0) => break, // stdin 关闭
            Err(_) => break,
            Ok(_) => {}
        }
        let cmd = line.trim();
        let words: Vec<&str> = cmd.split_whitespace().collect();
        match words.as_slice() {
            [] => {}
            ["quit"] | ["exit"] | ["q"] => break,
            ["help"] | ["h"] => print_help(),
            ["ls"] | ["list"] => {
                let tunnels = mgr.list();
                if tunnels.is_empty() {
                    println!("（无隧道）");
                }
                for t in tunnels {
                    println!(
                        "  {:<5} -> {}:{}   ({} 个活动连接)",
                        t.local_port, t.remote_host, t.remote_port, t.connections
                    );
                }
            }
            ["add", local, remote] => {
                let local_port: u16 = match local.parse() {
                    Ok(p) => p,
                    Err(_) => {
                        println!("端口格式错误：{local}");
                        continue;
                    }
                };
                match remote.split_once(':') {
                    Some((rh, rp)) => match rp.parse::<u32>() {
                        Ok(rp) => match mgr.add(local_port, rh, rp).await {
                            Ok(()) => {}
                            Err(e) => println!("[错误] {e}"),
                        },
                        Err(_) => println!("端口格式错误：{rp}"),
                    },
                    None => println!("远端目标格式应为 host:port"),
                }
            }
            ["rm", local] | ["remove", local] => {
                match local.parse::<u16>() {
                    Ok(port) => {
                        if let Err(e) = mgr.remove(port).await {
                            println!("[错误] {e}");
                        }
                    }
                    Err(_) => println!("端口格式错误：{local}"),
                }
            }
            _ => println!("未知命令：{cmd}（输入 help 查看帮助）"),
        }
        line.clear();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let (user, host) = args
        .target
        .split_once('@')
        .ok_or("目标格式应为 user@host，例如 root@example.com")?;

    let key_path = args.key.clone().unwrap_or_else(default_key_path);
    let mut mgr = TunnelManager::connect(user, host, args.ssh_port, &key_path).await?;
    println!("[OK] 已连接 {user}@{host}:{}，输入 help 查看命令", args.ssh_port);

    repl(&mut mgr).await;

    mgr.shutdown().await;
    println!("已断开连接");
    Ok(())
}