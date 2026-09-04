//! TUI 界面：多主机标签页切换 + 隧道列表视图 + 统一美观的新建连接/隧道弹窗。
//! 与 MultiTunnelManager 解耦：指令走 mpsc，状态回报走快照事件。

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Constraint::{Length, Min};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, List, Paragraph, Row, Table, TableState, Tabs,
};
use tokio::sync::{mpsc, oneshot};

use crate::tunnel::{
    list_ssh_config_hosts, resolve_target_str, AuthMethod, Command, ConnectionStatus,
    Event as TunnelEvent, HostSummary, RemotePort, SshConfigHost,
};

/// 界面模式
enum Mode {
    /// 列表浏览（浏览当前主机的隧道）
    List,
    /// 连接新主机弹窗（支持密码/私钥认证，内嵌 ~/.ssh/config 发现列表）
    ConnectHost,
    /// 新增隧道表单（在当前主机，内嵌远端服务自动发现）
    InputTunnel,
    /// 查看选中隧道的日志
    Log { port: u16, scroll: usize },
}

/// 认证类型
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthType {
    KeyFile,
    Password,
}

/// 连接主机表单焦点
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnectFocus {
    Target,
    AuthTypeToggle,
    AuthSecret,
    ConfigList,
}

/// 连接主机表单状态
struct FormConnectHost {
    focus: ConnectFocus,
    target: String,
    auth_type: AuthType,
    key_path: String,
    password: String,
    config_hosts: Vec<SshConfigHost>,
    config_selected: usize,
}

impl FormConnectHost {
    fn new() -> Self {
        let config_hosts = list_ssh_config_hosts();
        let focus = if !config_hosts.is_empty() {
            ConnectFocus::ConfigList
        } else {
            ConnectFocus::Target
        };
        Self {
            focus,
            target: String::new(),
            auth_type: AuthType::KeyFile,
            key_path: String::new(),
            password: String::new(),
            config_hosts,
            config_selected: 0,
        }
    }
}

/// 新增隧道表单焦点
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FormTunnelFocus {
    LocalPort,
    RemoteTarget,
    RemoteList,
}

/// 新增隧道表单状态
struct FormTunnel {
    session_id: String,
    focus: FormTunnelFocus,
    local_port: String,
    remote: String,
}

impl FormTunnel {
    fn new(session_id: String) -> Self {
        Self {
            session_id,
            focus: FormTunnelFocus::LocalPort,
            local_port: String::new(),
            remote: String::new(),
        }
    }

    /// 提交解析：返回 (本地端口, 远端 host, 远端端口)
    fn parse(&self) -> Result<(u16, String, u32), String> {
        let local_port: u16 = self
            .local_port
            .trim()
            .parse()
            .map_err(|_| format!("本地端口格式错误：{}", self.local_port.trim()))?;
        let remote = self.remote.trim();
        let (host, remote_port) = if remote.is_empty() {
            ("localhost".to_string(), local_port as u32)
        } else if remote.chars().all(|c| c.is_ascii_digit()) {
            let p: u32 = remote
                .parse()
                .map_err(|_| format!("远端端口格式错误：{remote}"))?;
            ("localhost".to_string(), p)
        } else {
            match remote.split_once(':') {
                Some((h, p)) => {
                    let host = h.trim();
                    if host.is_empty() {
                        return Err("远端 host 不能为空".into());
                    }
                    let port: u32 = p
                        .trim()
                        .parse()
                        .map_err(|_| format!("远端端口格式错误：{p}"))?;
                    (host.to_string(), port)
                }
                None => {
                    return Err(format!(
                        "远端目标格式应为 host:port 或只填端口：{remote}"
                    ))
                }
            }
        };
        Ok((local_port, host, remote_port))
    }
}

/// TUI 应用状态
pub(crate) struct App {
    cmd_tx: mpsc::Sender<Command>,
    event_rx: mpsc::UnboundedReceiver<TunnelEvent>,
    /// 所有已连接的主机列表
    hosts: Vec<HostSummary>,
    /// 当前选中的主机下标
    active_host: usize,
    /// 当前主机中选中的隧道下标
    selected_tunnel: usize,
    mode: Mode,
    form_connect: FormConnectHost,
    form_tunnel: FormTunnel,
    /// 待发送到后台的命令
    pending_cmds: Vec<Command>,
    /// 挂起的命令回执
    pending_reply: Option<(std::time::Instant, oneshot::Receiver<Result<(), String>>)>,
    /// 挂起的远端端口扫描回执：(session_id, receiver)
    pending_scan: Option<(String, oneshot::Receiver<Vec<RemotePort>>)>,
    /// 远端端口发现结果
    remote_ports: Vec<RemotePort>,
    ports_selected: usize,
    /// 状态消息：(内容, 是否错误)
    status: Option<(String, bool)>,
    quit: bool,
}

impl App {
    pub(crate) fn new(
        cmd_tx: mpsc::Sender<Command>,
        event_rx: mpsc::UnboundedReceiver<TunnelEvent>,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx,
            hosts: Vec::new(),
            active_host: 0,
            selected_tunnel: 0,
            mode: Mode::List,
            form_connect: FormConnectHost::new(),
            form_tunnel: FormTunnel::new(String::new()),
            pending_cmds: Vec::new(),
            pending_reply: None,
            pending_scan: None,
            remote_ports: Vec::new(),
            ports_selected: 0,
            status: None,
            quit: false,
        }
    }

    fn current_host(&self) -> Option<&HostSummary> {
        self.hosts.get(self.active_host)
    }

    pub(crate) async fn run(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
    ) -> io::Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;

            // 1. 键盘事件（非阻塞轮询）
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    self.on_key(key);
                }
            }

            // 2. 后台状态快照
            while let Ok(ev) = self.event_rx.try_recv() {
                match ev {
                    TunnelEvent::State { hosts } => {
                        self.hosts = hosts;
                        if !self.hosts.is_empty() {
                            self.active_host = self.active_host.min(self.hosts.len() - 1);
                            if let Some(h) = self.hosts.get(self.active_host) {
                                self.selected_tunnel = self
                                    .selected_tunnel
                                    .min(h.tunnels.len().saturating_sub(1));
                            }
                        } else {
                            self.active_host = 0;
                            self.selected_tunnel = 0;
                        }
                    }
                }
            }

            // 3. 发送待发命令
            for cmd in self.pending_cmds.drain(..) {
                if self.cmd_tx.send(cmd).await.is_err() {
                    self.status = Some(("后台任务已退出".into(), true));
                }
            }

            // 3.5 端口扫描回执
            if let Some((sess_id, rx)) = &mut self.pending_scan {
                if let Ok(ports) = rx.try_recv() {
                    if let Mode::InputTunnel = &self.mode {
                        if self.form_tunnel.session_id == *sess_id {
                            self.remote_ports = ports;
                            if !self.remote_ports.is_empty() {
                                self.ports_selected =
                                    self.ports_selected.min(self.remote_ports.len() - 1);
                            } else {
                                self.ports_selected = 0;
                            }
                        }
                    }
                    self.pending_scan = None;
                }
            }

            // 4. 命令回执
            if let Some((started, rx)) = &mut self.pending_reply {
                if let Ok(res) = rx.try_recv() {
                    match res {
                        Ok(()) => self.status = Some(("操作成功".into(), false)),
                        Err(e) => self.status = Some((e, true)),
                    }
                    self.pending_reply = None;
                } else if started.elapsed() > std::time::Duration::from_secs(10) {
                    self.status = Some(("后台命令超时，请重试".into(), true));
                    self.pending_reply = None;
                }
            }
        }
        let _ = self.cmd_tx.send(Command::Quit).await;
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match self.mode {
            Mode::List => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.quit = true
                }
                // 主机切换快捷键：H / L / Left / Right / [ / ]
                KeyCode::Char('H') | KeyCode::Left | KeyCode::Char('[') => {
                    if !self.hosts.is_empty() {
                        self.active_host = self.active_host.saturating_sub(1);
                        self.selected_tunnel = 0;
                    }
                }
                KeyCode::Char('L') | KeyCode::Right | KeyCode::Char(']') => {
                    if !self.hosts.is_empty() && self.active_host + 1 < self.hosts.len() {
                        self.active_host += 1;
                        self.selected_tunnel = 0;
                    }
                }
                // 数字键 1~9 直接切换主机标签
                KeyCode::Char(c @ '1'..='9') => {
                    let idx = (c as usize) - ('1' as usize);
                    if idx < self.hosts.len() {
                        self.active_host = idx;
                        self.selected_tunnel = 0;
                    }
                }
                // [n] 连接新主机
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.mode = Mode::ConnectHost;
                    self.form_connect = FormConnectHost::new();
                    self.status = None;
                }
                // [x] 断开当前主机
                KeyCode::Char('x') | KeyCode::Char('X') => {
                    self.disconnect_current_host();
                }
                // [r] 重新连接当前主机
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    if let Some(host) = self.current_host() {
                        let session_id = host.id.clone();
                        let (reply, rx) = oneshot::channel();
                        self.pending_cmds.push(Command::ReconnectHost {
                            session_id,
                            reply,
                        });
                        self.pending_reply = Some((std::time::Instant::now(), rx));
                        self.status = Some(("正在重连主机...".into(), false));
                    }
                }
                // [a] 在当前主机新建隧道
                KeyCode::Char('a') => {
                    if let Some(host) = self.current_host() {
                        let sess_id = host.id.clone();
                        self.mode = Mode::InputTunnel;
                        self.form_tunnel = FormTunnel::new(sess_id.clone());
                        self.remote_ports.clear();
                        self.ports_selected = 0;
                        self.status = None;
                        self.refresh_ports(&sess_id);
                    } else {
                        // 无主机时，自动打开连接主机弹窗
                        self.mode = Mode::ConnectHost;
                        self.form_connect = FormConnectHost::new();
                        self.status = None;
                    }
                }
                // [p] 在当前主机打开隧道并聚焦远端服务列表
                KeyCode::Char('p') => {
                    if let Some(host) = self.current_host() {
                        let sess_id = host.id.clone();
                        self.mode = Mode::InputTunnel;
                        self.form_tunnel = FormTunnel::new(sess_id.clone());
                        self.form_tunnel.focus = FormTunnelFocus::RemoteList;
                        self.remote_ports.clear();
                        self.ports_selected = 0;
                        self.status = None;
                        self.refresh_ports(&sess_id);
                    } else {
                        self.mode = Mode::ConnectHost;
                        self.form_connect = FormConnectHost::new();
                        self.status = None;
                    }
                }
                // [Space] 或 [s] 启用/停用当前选中的隧道
                KeyCode::Char(' ') | KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.toggle_selected_tunnel();
                }
                // [d] 删除当前主机选中的隧道
                KeyCode::Char('d') | KeyCode::Delete => self.remove_selected_tunnel(),
                KeyCode::Char('j') | KeyCode::Down => self.select_tunnel(1),
                KeyCode::Char('k') | KeyCode::Up => self.select_tunnel(-1),
                KeyCode::Char('l') => {
                    if let Some(host) = self.current_host() {
                        if let Some(t) = host.tunnels.get(self.selected_tunnel) {
                            self.mode = Mode::Log {
                                port: t.local_port,
                                scroll: 0,
                            };
                            self.status = None;
                        }
                    }
                }
                _ => {}
            },
            Mode::ConnectHost => {
                let has_config_hosts = !self.form_connect.config_hosts.is_empty();
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::List;
                        self.status = None;
                    }
                    KeyCode::Tab => {
                        self.form_connect.focus = match self.form_connect.focus {
                            ConnectFocus::Target => ConnectFocus::AuthTypeToggle,
                            ConnectFocus::AuthTypeToggle => ConnectFocus::AuthSecret,
                            ConnectFocus::AuthSecret => {
                                if has_config_hosts {
                                    ConnectFocus::ConfigList
                                } else {
                                    ConnectFocus::Target
                                }
                            }
                            ConnectFocus::ConfigList => ConnectFocus::Target,
                        };
                    }
                    KeyCode::BackTab => {
                        self.form_connect.focus = match self.form_connect.focus {
                            ConnectFocus::Target => {
                                if has_config_hosts {
                                    ConnectFocus::ConfigList
                                } else {
                                    ConnectFocus::AuthSecret
                                }
                            }
                            ConnectFocus::AuthTypeToggle => ConnectFocus::Target,
                            ConnectFocus::AuthSecret => ConnectFocus::AuthTypeToggle,
                            ConnectFocus::ConfigList => ConnectFocus::AuthSecret,
                        };
                    }
                    KeyCode::Down => match self.form_connect.focus {
                        ConnectFocus::Target => {
                            self.form_connect.focus = ConnectFocus::AuthTypeToggle;
                        }
                        ConnectFocus::AuthTypeToggle => {
                            self.form_connect.focus = ConnectFocus::AuthSecret;
                        }
                        ConnectFocus::AuthSecret => {
                            if has_config_hosts {
                                self.form_connect.focus = ConnectFocus::ConfigList;
                            }
                        }
                        ConnectFocus::ConfigList => {
                            if has_config_hosts {
                                self.form_connect.config_selected = (self
                                    .form_connect
                                    .config_selected
                                    + 1)
                                .min(self.form_connect.config_hosts.len() - 1);
                            }
                        }
                    },
                    KeyCode::Up => match self.form_connect.focus {
                        ConnectFocus::Target => {}
                        ConnectFocus::AuthTypeToggle => {
                            self.form_connect.focus = ConnectFocus::Target;
                        }
                        ConnectFocus::AuthSecret => {
                            self.form_connect.focus = ConnectFocus::AuthTypeToggle;
                        }
                        ConnectFocus::ConfigList => {
                            if self.form_connect.config_selected == 0 {
                                self.form_connect.focus = ConnectFocus::AuthSecret;
                            } else {
                                self.form_connect.config_selected =
                                    self.form_connect.config_selected.saturating_sub(1);
                            }
                        }
                    },
                    KeyCode::Left | KeyCode::Right => {
                        if self.form_connect.focus == ConnectFocus::AuthTypeToggle {
                            self.form_connect.auth_type =
                                if self.form_connect.auth_type == AuthType::KeyFile {
                                    AuthType::Password
                                } else {
                                    AuthType::KeyFile
                                };
                        }
                    }
                    KeyCode::Char('j') if self.form_connect.focus == ConnectFocus::ConfigList => {
                        if has_config_hosts {
                            self.form_connect.config_selected = (self
                                .form_connect
                                .config_selected
                                + 1)
                            .min(self.form_connect.config_hosts.len() - 1);
                        }
                    }
                    KeyCode::Char('k') if self.form_connect.focus == ConnectFocus::ConfigList => {
                        if self.form_connect.config_selected == 0 {
                            self.form_connect.focus = ConnectFocus::AuthSecret;
                        } else {
                            self.form_connect.config_selected =
                                self.form_connect.config_selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Char(' ') => match self.form_connect.focus {
                        ConnectFocus::AuthTypeToggle => {
                            self.form_connect.auth_type =
                                if self.form_connect.auth_type == AuthType::KeyFile {
                                    AuthType::Password
                                } else {
                                    AuthType::KeyFile
                                };
                        }
                        ConnectFocus::ConfigList => {
                            if let Some(cfg) = self
                                .form_connect
                                .config_hosts
                                .get(self.form_connect.config_selected)
                            {
                                self.form_connect.target = cfg.alias.clone();
                                self.form_connect.auth_type = AuthType::KeyFile;
                                self.form_connect.focus = ConnectFocus::Target;
                            }
                        }
                        ConnectFocus::AuthSecret => {
                            if self.form_connect.auth_type == AuthType::Password {
                                self.form_connect.password.push(' ');
                            }
                        }
                        ConnectFocus::Target => {
                            self.form_connect.target.push(' ');
                        }
                    },
                    KeyCode::Enter => match self.form_connect.focus {
                        ConnectFocus::ConfigList => {
                            if let Some(cfg) = self
                                .form_connect
                                .config_hosts
                                .get(self.form_connect.config_selected)
                                .cloned()
                            {
                                self.connect_from_config_host(&cfg);
                            }
                        }
                        ConnectFocus::Target
                        | ConnectFocus::AuthTypeToggle
                        | ConnectFocus::AuthSecret => {
                            self.submit_connect_host();
                        }
                    },
                    KeyCode::Backspace => match self.form_connect.focus {
                        ConnectFocus::Target => {
                            self.form_connect.target.pop();
                        }
                        ConnectFocus::AuthSecret => {
                            if self.form_connect.auth_type == AuthType::KeyFile {
                                self.form_connect.key_path.pop();
                            } else {
                                self.form_connect.password.pop();
                            }
                        }
                        ConnectFocus::AuthTypeToggle | ConnectFocus::ConfigList => {}
                    },
                    KeyCode::Char(c) => match self.form_connect.focus {
                        ConnectFocus::Target => {
                            self.form_connect.target.push(c);
                        }
                        ConnectFocus::AuthTypeToggle => {
                            if c == '1' || c == 'k' || c == 'K' {
                                self.form_connect.auth_type = AuthType::KeyFile;
                            } else if c == '2' || c == 'p' || c == 'P' {
                                self.form_connect.auth_type = AuthType::Password;
                            }
                        }
                        ConnectFocus::AuthSecret => {
                            if self.form_connect.auth_type == AuthType::KeyFile {
                                self.form_connect.key_path.push(c);
                            } else {
                                self.form_connect.password.push(c);
                            }
                        }
                        ConnectFocus::ConfigList => {}
                    },
                    _ => {}
                }
            }
            Mode::InputTunnel => {
                let has_ports = !self.remote_ports.is_empty();
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::List;
                        self.status = None;
                    }
                    KeyCode::Tab => {
                        self.form_tunnel.focus = match self.form_tunnel.focus {
                            FormTunnelFocus::LocalPort => FormTunnelFocus::RemoteTarget,
                            FormTunnelFocus::RemoteTarget => {
                                if has_ports {
                                    FormTunnelFocus::RemoteList
                                } else {
                                    FormTunnelFocus::LocalPort
                                }
                            }
                            FormTunnelFocus::RemoteList => FormTunnelFocus::LocalPort,
                        };
                    }
                    KeyCode::BackTab => {
                        self.form_tunnel.focus = match self.form_tunnel.focus {
                            FormTunnelFocus::LocalPort => {
                                if has_ports {
                                    FormTunnelFocus::RemoteList
                                } else {
                                    FormTunnelFocus::RemoteTarget
                                }
                            }
                            FormTunnelFocus::RemoteTarget => FormTunnelFocus::LocalPort,
                            FormTunnelFocus::RemoteList => FormTunnelFocus::RemoteTarget,
                        };
                    }
                    KeyCode::Down => match self.form_tunnel.focus {
                        FormTunnelFocus::LocalPort => {
                            self.form_tunnel.focus = FormTunnelFocus::RemoteTarget;
                        }
                        FormTunnelFocus::RemoteTarget => {
                            if has_ports {
                                self.form_tunnel.focus = FormTunnelFocus::RemoteList;
                            }
                        }
                        FormTunnelFocus::RemoteList => {
                            if has_ports {
                                self.ports_selected =
                                    (self.ports_selected + 1).min(self.remote_ports.len() - 1);
                            }
                        }
                    },
                    KeyCode::Up => match self.form_tunnel.focus {
                        FormTunnelFocus::LocalPort => {}
                        FormTunnelFocus::RemoteTarget => {
                            self.form_tunnel.focus = FormTunnelFocus::LocalPort;
                        }
                        FormTunnelFocus::RemoteList => {
                            if self.ports_selected == 0 {
                                self.form_tunnel.focus = FormTunnelFocus::RemoteTarget;
                            } else {
                                self.ports_selected = self.ports_selected.saturating_sub(1);
                            }
                        }
                    },
                    KeyCode::Char('j')
                        if self.form_tunnel.focus == FormTunnelFocus::RemoteList =>
                    {
                        if has_ports {
                            self.ports_selected =
                                (self.ports_selected + 1).min(self.remote_ports.len() - 1);
                        }
                    }
                    KeyCode::Char('k')
                        if self.form_tunnel.focus == FormTunnelFocus::RemoteList =>
                    {
                        if self.ports_selected == 0 {
                            self.form_tunnel.focus = FormTunnelFocus::RemoteTarget;
                        } else {
                            self.ports_selected = self.ports_selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Char('r') | KeyCode::Char('R')
                        if self.form_tunnel.focus == FormTunnelFocus::RemoteList =>
                    {
                        let sess = self.form_tunnel.session_id.clone();
                        self.refresh_ports(&sess);
                    }
                    KeyCode::Char(' ')
                        if self.form_tunnel.focus == FormTunnelFocus::RemoteList =>
                    {
                        if let Some(rp) = self.remote_ports.get(self.ports_selected).cloned() {
                            self.fill_form_from_port(&rp);
                        }
                    }
                    KeyCode::Enter => match self.form_tunnel.focus {
                        FormTunnelFocus::LocalPort => {
                            if self.form_tunnel.local_port.trim().is_empty() {
                                if has_ports {
                                    self.form_tunnel.focus = FormTunnelFocus::RemoteList;
                                } else {
                                    self.form_tunnel.focus = FormTunnelFocus::RemoteTarget;
                                }
                            } else if self.form_tunnel.remote.trim().is_empty() {
                                self.submit_tunnel_form();
                            } else {
                                self.submit_tunnel_form();
                            }
                        }
                        FormTunnelFocus::RemoteTarget => {
                            self.submit_tunnel_form();
                        }
                        FormTunnelFocus::RemoteList => {
                            if let Some(rp) = self.remote_ports.get(self.ports_selected).cloned() {
                                self.add_tunnel_from_port(&rp);
                            }
                        }
                    },
                    KeyCode::Backspace => match self.form_tunnel.focus {
                        FormTunnelFocus::LocalPort => {
                            self.form_tunnel.local_port.pop();
                        }
                        FormTunnelFocus::RemoteTarget => {
                            self.form_tunnel.remote.pop();
                        }
                        FormTunnelFocus::RemoteList => {}
                    },
                    KeyCode::Char(c) => match self.form_tunnel.focus {
                        FormTunnelFocus::LocalPort => {
                            if c.is_ascii_digit() {
                                self.form_tunnel.local_port.push(c);
                            }
                        }
                        FormTunnelFocus::RemoteTarget => {
                            self.form_tunnel.remote.push(c);
                        }
                        FormTunnelFocus::RemoteList => {}
                    },
                    _ => {}
                }
            }
            Mode::Log { port, scroll } => {
                let mut new_scroll = scroll;
                let mut back = false;
                match key.code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        if let Some(host) = self.current_host() {
                            if let Some(t) = host.tunnels.iter().find(|t| t.local_port == port) {
                                new_scroll = (new_scroll + 1).min(t.log.len().saturating_sub(1));
                            }
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        new_scroll = new_scroll.saturating_sub(1);
                    }
                    KeyCode::Char('g') => new_scroll = 0,
                    KeyCode::Char('G') => {
                        if let Some(host) = self.current_host() {
                            if let Some(t) = host.tunnels.iter().find(|t| t.local_port == port) {
                                new_scroll = t.log.len().saturating_sub(1);
                            }
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Esc => back = true,
                    _ => {}
                }
                if back {
                    self.mode = Mode::List;
                } else {
                    self.mode = Mode::Log {
                        port,
                        scroll: new_scroll,
                    };
                }
            }
        }
    }

    fn select_tunnel(&mut self, delta: isize) {
        let Some(host) = self.current_host() else {
            return;
        };
        if host.tunnels.is_empty() {
            return;
        }
        let len = host.tunnels.len() as isize;
        self.selected_tunnel =
            ((self.selected_tunnel as isize + delta).rem_euclid(len)) as usize;
    }

    fn remove_selected_tunnel(&mut self) {
        let Some(host) = self.current_host() else {
            return;
        };
        let Some(t) = host.tunnels.get(self.selected_tunnel) else {
            return;
        };
        let session_id = host.id.clone();
        let local_port = t.local_port;
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::RemoveTunnel {
            session_id: session_id.clone(),
            local_port,
            reply: tx,
        });
        self.pending_reply = Some((std::time::Instant::now(), rx));
        self.status = Some((
            format!("正在删除主机 [{session_id}] 的隧道 {local_port}…"),
            false,
        ));
    }

    fn toggle_selected_tunnel(&mut self) {
        let Some(host) = self.current_host() else {
            return;
        };
        let Some(t) = host.tunnels.get(self.selected_tunnel) else {
            return;
        };
        let session_id = host.id.clone();
        let local_port = t.local_port;
        let (tx, rx) = oneshot::channel();
        if t.enabled {
            self.pending_cmds.push(Command::DisableTunnel {
                session_id: session_id.clone(),
                local_port,
                reply: tx,
            });
            self.pending_reply = Some((std::time::Instant::now(), rx));
            self.status = Some((
                format!("正在停用主机 [{session_id}] 的隧道 {local_port}…"),
                false,
            ));
        } else {
            self.pending_cmds.push(Command::EnableTunnel {
                session_id: session_id.clone(),
                local_port,
                reply: tx,
            });
            self.pending_reply = Some((std::time::Instant::now(), rx));
            self.status = Some((
                format!("正在启用主机 [{session_id}] 的隧道 {local_port}…"),
                false,
            ));
        }
    }

    fn disconnect_current_host(&mut self) {
        let Some(host) = self.current_host() else {
            return;
        };
        let session_id = host.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::DisconnectHost {
            session_id: session_id.clone(),
            reply: tx,
        });
        self.pending_reply = Some((std::time::Instant::now(), rx));
        self.status = Some((format!("正在断开主机 [{session_id}]…"), false));
    }

    fn submit_connect_host(&mut self) {
        let target = self.form_connect.target.trim();
        if target.is_empty() {
            self.status = Some((
                "请输入目标主机（如 user@host 或 ~/.ssh/config 别名）".into(),
                true,
            ));
            return;
        }
        let auth = match self.form_connect.auth_type {
            AuthType::KeyFile => {
                let key = if self.form_connect.key_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.form_connect.key_path.trim()))
                };
                key.map(AuthMethod::KeyFile)
            }
            AuthType::Password => Some(AuthMethod::Password(self.form_connect.password.clone())),
        };
        match resolve_target_str(target, auth, 22, false) {
            Err(e) => {
                self.status = Some((e, true));
            }
            Ok(params) => {
                let display_name = params.display_name();
                let (tx, rx) = oneshot::channel();
                self.pending_cmds.push(Command::ConnectHost {
                    params,
                    reply: tx,
                });
                self.pending_reply = Some((std::time::Instant::now(), rx));
                self.mode = Mode::List;
                self.status = Some((format!("正在连接主机 [{display_name}]…"), false));
            }
        }
    }

    fn connect_from_config_host(&mut self, cfg_host: &SshConfigHost) {
        let params = cfg_host.to_connect_params(true);
        let display_name = params.display_name();
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::ConnectHost {
            params,
            reply: tx,
        });
        self.pending_reply = Some((std::time::Instant::now(), rx));
        self.mode = Mode::List;
        self.status = Some((format!("正在连接已知主机 [{display_name}]…"), false));
    }

    fn refresh_ports(&mut self, session_id: &str) {
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::ScanPorts {
            session_id: session_id.to_string(),
            reply: tx,
        });
        self.pending_scan = Some((session_id.to_string(), rx));
    }

    fn port_free(port: u16) -> bool {
        std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
    }

    fn add_tunnel_from_port(&mut self, rp: &RemotePort) {
        let session_id = self.form_tunnel.session_id.clone();
        let mut local = rp.port;
        while !Self::port_free(local) && local < 65535 {
            local += 1;
        }
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::AddTunnel {
            session_id: session_id.clone(),
            local_port: local,
            remote_host: "localhost".to_string(),
            remote_port: rp.port as u32,
            reply: tx,
        });
        self.pending_reply = Some((std::time::Instant::now(), rx));
        let hint = if local == rp.port {
            String::new()
        } else {
            format!("（本地端口已被占用，自动分配为 {}）", local)
        };
        self.mode = Mode::List;
        self.status = Some((
            format!(
                "正在向主机 [{session_id}] 添加隧道 {local} -> localhost:{} {hint}",
                rp.port
            ),
            false,
        ));
    }

    fn fill_form_from_port(&mut self, rp: &RemotePort) {
        let mut local = rp.port;
        while !Self::port_free(local) && local < 65535 {
            local += 1;
        }
        self.form_tunnel.local_port = local.to_string();
        self.form_tunnel.remote = format!("localhost:{}", rp.port);
        self.form_tunnel.focus = FormTunnelFocus::LocalPort;
        if local != rp.port {
            self.status = Some((
                format!(
                    "已自动填入端口 {}（原本地端口已被占用，推荐可用端口 {}）",
                    rp.port, local
                ),
                false,
            ));
        } else {
            self.status = Some((
                format!("已自动填入端口 {}，可按需修改本地端口后回车提交", rp.port),
                false,
            ));
        }
    }

    fn submit_tunnel_form(&mut self) {
        let session_id = self.form_tunnel.session_id.clone();
        match self.form_tunnel.parse() {
            Err(e) => {
                self.status = Some((e, true));
            }
            Ok((local_port, host, remote_port)) => {
                let (tx, rx) = oneshot::channel();
                self.pending_cmds.push(Command::AddTunnel {
                    session_id: session_id.clone(),
                    local_port,
                    remote_host: host,
                    remote_port,
                    reply: tx,
                });
                self.pending_reply = Some((std::time::Instant::now(), rx));
                self.mode = Mode::List;
                self.status = Some((
                    format!("正在向主机 [{session_id}] 添加隧道 {local_port}…"),
                    false,
                ));
            }
        }
    }

    // ---------- 渲染 ----------

    fn fmt_rate(bytes: u64) -> String {
        let b = bytes as f64;
        if b >= 1024.0 * 1024.0 {
            format!("{:.1} MB/s", b / 1024.0 / 1024.0)
        } else if b >= 1024.0 {
            format!("{:.1} KB/s", b / 1024.0)
        } else {
            format!("{b} B/s")
        }
    }

    fn fmt_bytes(bytes: u64) -> String {
        let b = bytes as f64;
        if b >= 1024.0 * 1024.0 {
            format!("{:.1} MB", b / 1024.0 / 1024.0)
        } else if b >= 1024.0 {
            format!("{:.1} KB", b / 1024.0)
        } else {
            format!("{b} B")
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
            let w = width.min(area.width.saturating_sub(2));
            let h = height.min(area.height.saturating_sub(2));
            let x = area.x + area.width.saturating_sub(w) / 2;
            let y = area.y + area.height.saturating_sub(h) / 2;
            Rect::new(x, y, w, h)
        }

        let [tabs_area, host_info_area, list, footer] = Layout::vertical([
            Length(3), // 主机标签页栏（融合 ⚡ mtui 品牌标题与动态状态通知）
            Length(1), // 当前主机连接状态条
            Min(0),    // 隧道列表 / 欢迎区域
            Length(1), // 底部操作提示
        ])
        .areas(f.area());

        // 1. 主机标签页栏 (Tabs，融合 ⚡ mtui 品牌标题与状态通知)
        let border_style = if let Some((_, is_err)) = &self.status {
            if *is_err {
                Style::new().fg(Color::Red).bold()
            } else {
                Style::new().fg(Color::Green)
            }
        } else {
            Style::new().fg(Color::Cyan)
        };

        if self.hosts.is_empty() {
            let mut title_spans = vec![
                Span::styled(" ⚡ mtui ", Style::new().fg(Color::Cyan).bold()),
                Span::styled("· 多主机 SSH 动态隧道管理 ", Style::new().bold()),
            ];
            if let Some((msg, is_err)) = &self.status {
                let (icon, color) = if *is_err {
                    ("✖ ", Color::Red)
                } else {
                    ("✔ ", Color::Green)
                };
                title_spans.push(Span::styled("· ", Style::new().fg(Color::DarkGray)));
                title_spans.push(Span::styled(
                    format!("{icon}{msg} "),
                    Style::new().fg(color).bold(),
                ));
            } else {
                title_spans.push(Span::styled(
                    "(0 台主机已连接) ",
                    Style::new().fg(Color::DarkGray),
                ));
            }
            f.render_widget(
                Paragraph::new("  ○ 当前未连接任何 SSH 主机 · 按 [n] 连接新主机")
                    .style(Style::new().fg(Color::Yellow))
                    .block(
                        Block::new()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .border_style(border_style)
                            .title(Line::from(title_spans)),
                    ),
                tabs_area,
            );
        } else {
            let mut titles: Vec<Line> = self
                .hosts
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    let (icon, color) = match h.status {
                        ConnectionStatus::Connected => ("●", Color::Green),
                        ConnectionStatus::Reconnecting(_) => ("◐", Color::Yellow),
                        ConnectionStatus::Disconnected => ("○", Color::Red),
                    };
                    let num = i + 1;
                    let count = h.tunnels.len();
                    Line::from(vec![
                        Span::styled(format!("[{num}] "), Style::new().fg(Color::DarkGray)),
                        Span::styled(format!("{icon} "), Style::new().fg(color)),
                        Span::styled(h.display_name.clone(), Style::new().bold()),
                        Span::styled(format!(" ({count})"), Style::new().fg(Color::DarkGray)),
                    ])
                })
                .collect();
            titles.push(Line::from(vec![Span::styled(
                " [+] 新建主机 (n) ",
                Style::new().fg(Color::DarkGray),
            )]));

            let mut title_spans = vec![
                Span::styled(" ⚡ mtui ", Style::new().fg(Color::Cyan).bold()),
                Span::styled("· 主机列表 ", Style::new().bold()),
                Span::styled(
                    format!("({} 台主机 · [1-9/H/L] 快速切换) ", self.hosts.len()),
                    Style::new().fg(Color::DarkGray),
                ),
            ];
            if let Some((msg, is_err)) = &self.status {
                let (icon, color) = if *is_err {
                    ("✖ ", Color::Red)
                } else {
                    ("✔ ", Color::Green)
                };
                title_spans.push(Span::styled("· ", Style::new().fg(Color::DarkGray)));
                title_spans.push(Span::styled(
                    format!("{icon}{msg} "),
                    Style::new().fg(color).bold(),
                ));
            }

            let tabs = Tabs::new(titles)
                .select(self.active_host)
                .block(
                    Block::new()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(border_style)
                        .title(Line::from(title_spans)),
                )
                .highlight_style(
                    Style::new()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .divider(" | ");
            f.render_widget(tabs, tabs_area);
        }

        // 3. 当前主机连接状态条
        if let Some(host) = self.current_host() {
            let (status_text, status_style) = match host.status {
                ConnectionStatus::Connected => ("● 已连接", Style::new().fg(Color::Green).bold()),
                ConnectionStatus::Reconnecting(_n) => (
                    "◐ 重连中…",
                    Style::new().fg(Color::Yellow).bold(),
                ),
                ConnectionStatus::Disconnected => {
                    ("○ 已断开", Style::new().fg(Color::Red).bold())
                }
            };
            let info_line = Line::from(vec![
                Span::styled(" 当前主机: ", Style::new().fg(Color::Gray)),
                Span::styled(
                    format!(
                        "{}@{}:{}",
                        host.params.user, host.params.host, host.params.ssh_port
                    ),
                    Style::new().fg(Color::White).bold(),
                ),
                Span::styled("  ·  状态: ", Style::new().fg(Color::Gray)),
                Span::styled(status_text, status_style),
                Span::styled("  ·  实时速率: ", Style::new().fg(Color::Gray)),
                Span::styled(
                    format!(
                        "↓ {}  ↑ {}",
                        Self::fmt_rate(host.total_rx_rate),
                        Self::fmt_rate(host.total_tx_rate)
                    ),
                    Style::new().fg(Color::Cyan),
                ),
            ]);
            f.render_widget(Paragraph::new(info_line), host_info_area);
        }

        // 4. 隧道列表 或 欢迎区
        if !matches!(self.mode, Mode::Log { .. }) {
            if let Some(host) = self.current_host() {
                if host.tunnels.is_empty() {
                    f.render_widget(
                        Paragraph::new("  ○ 当前主机暂无隧道 · 按 [a] 新建端口转发或发现远端服务")
                            .style(Style::new().fg(Color::DarkGray))
                            .block(
                                Block::new()
                                    .borders(Borders::ALL)
                                    .border_type(BorderType::Rounded)
                                    .title(format!(" 隧道列表 ({}) ", host.display_name)),
                            ),
                        list,
                    );
                } else {
                    let rows: Vec<Row> = host
                        .tunnels
                        .iter()
                        .map(|t| {
                            let (status_str, status_style) = if t.enabled {
                                ("● 运行中", Style::new().fg(Color::Green))
                            } else {
                                ("○ 已停用", Style::new().fg(Color::DarkGray))
                            };
                            let (conn_str, rx_rate_str, tx_rate_str) = if t.enabled {
                                (
                                    t.connections.to_string(),
                                    Self::fmt_rate(t.rx_rate),
                                    Self::fmt_rate(t.tx_rate),
                                )
                            } else {
                                ("-".to_string(), "-".to_string(), "-".to_string())
                            };
                            let row_style = if t.enabled {
                                Style::default()
                            } else {
                                Style::default().fg(Color::DarkGray)
                            };
                            Row::new(vec![
                                Cell::from(status_str).style(status_style),
                                Cell::from(t.local_port.to_string()),
                                Cell::from(format!("{}:{}", t.remote_host, t.remote_port)),
                                Cell::from(conn_str),
                                Cell::from(rx_rate_str),
                                Cell::from(tx_rate_str),
                                Cell::from(Self::fmt_bytes(t.rx_bytes)),
                                Cell::from(Self::fmt_bytes(t.tx_bytes)),
                            ])
                            .style(row_style)
                        })
                        .collect();
                    let active_count = host.tunnels.iter().filter(|t| t.enabled).count();
                    let table = Table::new(
                        rows,
                        [
                            Constraint::Length(9),
                            Constraint::Length(10),
                            Constraint::Length(22),
                            Constraint::Length(6),
                            Constraint::Length(10),
                            Constraint::Length(10),
                            Constraint::Length(10),
                            Constraint::Length(10),
                        ],
                    )
                    .header(
                        Row::new(vec![
                            "状态", "本地端口", "远端目标", "连接", "↓速率", "↑速率", "↓累计", "↑累计",
                        ])
                        .style(Style::new().fg(Color::White).bold()),
                    )
                    .block(
                        Block::new()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .title(format!(
                                " 隧道列表 ({}) · 共 {} 条 ({} 运行中) ",
                                host.display_name,
                                host.tunnels.len(),
                                active_count
                            )),
                    )
                    .row_highlight_style(
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
                    );
                    let mut state = ratatui::widgets::TableState::new()
                        .with_selected(Some(self.selected_tunnel));
                    f.render_stateful_widget(table, list, &mut state);
                }
            } else {
                // 没有主机连接时的空状态展示
                let welcome_msg = vec![
                    Line::from(""),
                    Line::from(vec![Span::styled(
                        "✨ 欢迎使用 mtui 动态 SSH 隧道管理",
                        Style::new().fg(Color::Cyan).bold(),
                    )]),
                    Line::from(""),
                    Line::from("当前未连接任何 SSH 主机。你可以："),
                    Line::from(vec![
                        Span::styled("  • 按 ", Style::new().fg(Color::DarkGray)),
                        Span::styled("[n]", Style::new().fg(Color::Yellow).bold()),
                        Span::styled(
                            " 连接新主机（支持输入 user@host、密码/私钥认证或直接读取 ~/.ssh/config 别名）",
                            Style::new().fg(Color::Gray),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("  • 按 ", Style::new().fg(Color::DarkGray)),
                        Span::styled("[q]", Style::new().fg(Color::Red).bold()),
                        Span::styled(" 退出程序", Style::new().fg(Color::Gray)),
                    ]),
                ];
                f.render_widget(
                    Paragraph::new(welcome_msg).block(
                        Block::new()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .title(" 开始使用 "),
                    ),
                    list,
                );
            }
        }

        // 5. 底栏帮助 / 日志视图
        match self.mode {
            Mode::List | Mode::ConnectHost | Mode::InputTunnel => {
                let help = " [1-9/H/L]切换主机  [n]连接主机  [x]断开主机  [r]重连  [a]新建隧道  [Space/s]启停  [d]删除  [l]日志  [q]退出";
                f.render_widget(
                    Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
                    footer,
                );
            }
            Mode::Log { port, scroll } => {
                let tunnel = self
                    .current_host()
                    .and_then(|h| h.tunnels.iter().find(|t| t.local_port == port));
                let status_label = if tunnel.map(|t| t.enabled).unwrap_or(false) {
                    "运行中"
                } else {
                    "已停用"
                };
                let log: Vec<String> = tunnel.map(|t| t.log.clone()).unwrap_or_default();
                let lines: Vec<ratatui::widgets::ListItem> = log
                    .iter()
                    .skip(scroll)
                    .map(|l| ratatui::widgets::ListItem::new(l.clone()))
                    .collect();
                f.render_widget(
                    List::new(lines).block(
                        Block::new()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Rounded)
                            .title(format!(" 隧道 {port} 日志 ({status_label}) ")),
                    ),
                    list,
                );
                let help = format!(
                    " [↑/↓]滚动  [g/G]首/尾  [q/Esc]返回    共 {} 条",
                    log.len()
                );
                f.render_widget(
                    Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
                    footer,
                );
            }
        }

        // 6. 弹窗 1：连接新主机 (Mode::ConnectHost)
        if matches!(self.mode, Mode::ConnectHost) {
            let popup = centered_rect(76, 19, f.area());
            f.render_widget(Clear, popup);

            let modal_block = Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" 🌐 连接 SSH 远程主机 (Connect Host) ")
                .title_style(Style::new().fg(Color::Cyan).bold())
                .border_style(Style::new().fg(Color::Cyan));
            f.render_widget(modal_block.clone(), popup);

            let inner = modal_block.inner(popup);
            let [form_section, config_section, hint_section] = Layout::vertical([
                Length(5), // 手动输入区：目标主机 + 认证方式切换 + 凭据输入
                Min(7),    // ~/.ssh/config 发现列表区
                Length(2), // 底部操作提示
            ])
            .areas(inner);

            // 手动输入
            let [target_line, auth_type_line, secret_line, _space] =
                Layout::vertical([Length(1), Length(1), Length(1), Length(1)])
                    .areas(form_section);

            // 1. 目标主机输入
            let target_focused = self.form_connect.focus == ConnectFocus::Target;
            let target_val = if self.form_connect.target.is_empty() {
                if target_focused {
                    "█".to_string()
                } else {
                    "user@host:port 或 ~/.ssh/config 别名".to_string()
                }
            } else if target_focused {
                format!("{}█", self.form_connect.target)
            } else {
                self.form_connect.target.clone()
            };
            let target_style = if target_focused {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else if self.form_connect.target.is_empty() {
                Style::new().fg(Color::DarkGray)
            } else {
                Style::new().fg(Color::White).bold()
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        if target_focused {
                            "▶ 目标主机: "
                        } else {
                            "  目标主机: "
                        },
                        if target_focused {
                            Style::new().fg(Color::Cyan).bold()
                        } else {
                            Style::new().fg(Color::Gray)
                        },
                    ),
                    Span::styled(format!(" {target_val} "), target_style),
                ])),
                target_line,
            );

            // 2. 认证方式切换
            let is_auth_toggle_focused =
                self.form_connect.focus == ConnectFocus::AuthTypeToggle;
            let (key_radio, pwd_radio) = match self.form_connect.auth_type {
                AuthType::KeyFile => ("(●) 🔑 私钥认证", "(○) 🔒 密码认证"),
                AuthType::Password => ("(○) 🔑 私钥认证", "(●) 🔒 密码认证"),
            };
            let toggle_prefix = if is_auth_toggle_focused {
                "▶ 认证方式: "
            } else {
                "  认证方式: "
            };
            let toggle_prefix_style = if is_auth_toggle_focused {
                Style::new().fg(Color::Cyan).bold()
            } else {
                Style::new().fg(Color::Gray)
            };

            let (key_style, pwd_style) = match self.form_connect.auth_type {
                AuthType::KeyFile => (
                    if is_auth_toggle_focused {
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                    } else {
                        Style::new().fg(Color::Cyan).bold()
                    },
                    Style::new().fg(Color::DarkGray),
                ),
                AuthType::Password => (
                    Style::new().fg(Color::DarkGray),
                    if is_auth_toggle_focused {
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                    } else {
                        Style::new().fg(Color::Cyan).bold()
                    },
                ),
            };

            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(toggle_prefix, toggle_prefix_style),
                    Span::styled(format!(" {key_radio} "), key_style),
                    Span::raw("   "),
                    Span::styled(format!(" {pwd_radio} "), pwd_style),
                    Span::styled(
                        "   (按 空格 或 ←/→ 切换)",
                        Style::new().fg(Color::DarkGray),
                    ),
                ])),
                auth_type_line,
            );

            // 3. 私钥路径 或 密码输入
            let is_secret_focused = self.form_connect.focus == ConnectFocus::AuthSecret;
            match self.form_connect.auth_type {
                AuthType::KeyFile => {
                    let key_val = if self.form_connect.key_path.is_empty() {
                        if is_secret_focused {
                            "█".to_string()
                        } else {
                            "~/.ssh/id_ed25519 (默认)".to_string()
                        }
                    } else if is_secret_focused {
                        format!("{}█", self.form_connect.key_path)
                    } else {
                        self.form_connect.key_path.clone()
                    };
                    let key_style = if is_secret_focused {
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                    } else if self.form_connect.key_path.is_empty() {
                        Style::new().fg(Color::DarkGray)
                    } else {
                        Style::new().fg(Color::White).bold()
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled(
                                if is_secret_focused {
                                    "▶ 私钥路径: "
                                } else {
                                    "  私钥路径: "
                                },
                                if is_secret_focused {
                                    Style::new().fg(Color::Cyan).bold()
                                } else {
                                    Style::new().fg(Color::Gray)
                                },
                            ),
                            Span::styled(format!(" {key_val} "), key_style),
                        ])),
                        secret_line,
                    );
                }
                AuthType::Password => {
                    let masked = "•".repeat(self.form_connect.password.len());
                    let pwd_val = if self.form_connect.password.is_empty() {
                        if is_secret_focused {
                            "█".to_string()
                        } else {
                            "请输入 SSH 登录密码".to_string()
                        }
                    } else if is_secret_focused {
                        format!("{}█", masked)
                    } else {
                        masked
                    };
                    let pwd_style = if is_secret_focused {
                        Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                    } else if self.form_connect.password.is_empty() {
                        Style::new().fg(Color::DarkGray)
                    } else {
                        Style::new().fg(Color::Yellow).bold()
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled(
                                if is_secret_focused {
                                    "▶ 登录密码: "
                                } else {
                                    "  登录密码: "
                                },
                                if is_secret_focused {
                                    Style::new().fg(Color::Cyan).bold()
                                } else {
                                    Style::new().fg(Color::Gray)
                                },
                            ),
                            Span::styled(format!(" {pwd_val} "), pwd_style),
                        ])),
                        secret_line,
                    );
                }
            }

            // ~/.ssh/config 发现列表
            let is_cfg_focused = self.form_connect.focus == ConnectFocus::ConfigList;
            let cfg_block = Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(format!(
                    " 📋 ~/.ssh/config 发现的主机 ({} 个 · 回车一键连接 / 空格填入) ",
                    self.form_connect.config_hosts.len()
                ))
                .title_style(if is_cfg_focused {
                    Style::new().fg(Color::Yellow).bold()
                } else {
                    Style::new().fg(Color::Gray)
                })
                .border_style(if is_cfg_focused {
                    Style::new().fg(Color::Yellow).bold()
                } else {
                    Style::new().fg(Color::DarkGray)
                });

            if self.form_connect.config_hosts.is_empty() {
                f.render_widget(
                    Paragraph::new(
                        "  ○ 未在 ~/.ssh/config 中发现有效主机配置，请在上方手动输入",
                    )
                    .style(Style::new().fg(Color::DarkGray))
                    .block(cfg_block),
                    config_section,
                );
            } else {
                let rows: Vec<Row> = self
                    .form_connect
                    .config_hosts
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        let is_sel = is_cfg_focused && i == self.form_connect.config_selected;
                        let prefix = if is_sel { "▶ " } else { "  " };
                        let is_connected = self.hosts.iter().any(|sh| sh.id == h.alias);
                        let status_cell = if is_connected {
                            Span::styled("● 已连接", Style::new().fg(Color::Green))
                        } else {
                            Span::styled("○ 未连接", Style::new().fg(Color::DarkGray))
                        };
                        Row::new(vec![
                            Cell::from(Span::styled(
                                format!("{}{}", prefix, h.alias),
                                if is_sel {
                                    Style::new().fg(Color::Yellow).bold()
                                } else {
                                    Style::new().fg(Color::Cyan)
                                },
                            )),
                            Cell::from(Span::styled(
                                h.host_name.clone(),
                                Style::new().fg(Color::White),
                            )),
                            Cell::from(Span::styled(
                                if h.user.is_empty() {
                                    "（默认）"
                                } else {
                                    &h.user
                                },
                                Style::new().fg(Color::Gray),
                            )),
                            Cell::from(Span::styled(
                                h.port.to_string(),
                                Style::new().fg(Color::Gray),
                            )),
                            Cell::from(status_cell),
                        ])
                    })
                    .collect();
                let table = Table::new(
                    rows,
                    [
                        Constraint::Length(18),
                        Constraint::Length(22),
                        Constraint::Length(12),
                        Constraint::Length(8),
                        Constraint::Min(10),
                    ],
                )
                .header(
                    Row::new(vec!["  别名", "主机地址", "用户", "端口", "状态"])
                        .style(Style::new().fg(Color::Gray).bold()),
                )
                .block(cfg_block)
                .row_highlight_style(if is_cfg_focused {
                    Style::new().fg(Color::Black).bg(Color::Yellow).bold()
                } else {
                    Style::new().fg(Color::White).bg(Color::DarkGray)
                });
                let mut state = TableState::new()
                    .with_selected(Some(self.form_connect.config_selected));
                f.render_stateful_widget(table, config_section, &mut state);
            }

            // 底部提示
            let hint_line = match self.form_connect.focus {
                ConnectFocus::Target
                | ConnectFocus::AuthTypeToggle
                | ConnectFocus::AuthSecret => Line::from(vec![
                    Span::styled(" [Tab/Shift-Tab] ", Style::new().fg(Color::Yellow)),
                    Span::raw("切换焦点   "),
                    Span::styled(" [Enter] ", Style::new().fg(Color::Green)),
                    Span::raw("确认连接   "),
                    Span::styled(" [↓] ", Style::new().fg(Color::Cyan)),
                    Span::raw("选配置列表   "),
                    Span::styled(" [Esc] ", Style::new().fg(Color::Red)),
                    Span::raw("取消"),
                ]),
                ConnectFocus::ConfigList => Line::from(vec![
                    Span::styled(" [Enter] ", Style::new().fg(Color::Green).bold()),
                    Span::styled("⚡一键连接   ", Style::new().fg(Color::Green).bold()),
                    Span::styled(" [Space] ", Style::new().fg(Color::Cyan)),
                    Span::raw("填入表单修改   "),
                    Span::styled(" [↑/↓/j/k] ", Style::new().fg(Color::Yellow)),
                    Span::raw("选择   "),
                    Span::styled(" [Tab/Esc] ", Style::new().fg(Color::Gray)),
                    Span::raw("返回输入/取消"),
                ]),
            };
            f.render_widget(
                Paragraph::new(hint_line)
                    .alignment(Alignment::Center)
                    .style(Style::new().fg(Color::DarkGray)),
                hint_section,
            );
        }

        // 7. 弹窗 2：新建隧道 (Mode::InputTunnel)
        if matches!(self.mode, Mode::InputTunnel) {
            let popup = centered_rect(76, 18, f.area());
            f.render_widget(Clear, popup);

            let host_name = self.form_tunnel.session_id.clone();
            let modal_block = Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(format!(" ➕ 新建隧道 / 端口转发 · 目标主机 [{host_name}] "))
                .title_style(Style::new().fg(Color::Cyan).bold())
                .border_style(Style::new().fg(Color::Cyan));
            f.render_widget(modal_block.clone(), popup);

            let inner = modal_block.inner(popup);
            let [form_section, ports_section, hint_section] = Layout::vertical([
                Length(4), // 表单输入区
                Min(8),    // 远端服务列表区
                Length(2), // 底部操作提示区
            ])
            .areas(inner);

            // 表单输入
            let [local_line, remote_line, _space] =
                Layout::vertical([Length(1), Length(1), Length(1)]).areas(form_section);

            let local_focused = self.form_tunnel.focus == FormTunnelFocus::LocalPort;
            let local_prefix = if local_focused {
                "▶ 本地监听端口: "
            } else {
                "  本地监听端口: "
            };
            let local_val = if self.form_tunnel.local_port.is_empty() {
                if local_focused {
                    "█".to_string()
                } else {
                    "（必填，例如 8080）".to_string()
                }
            } else if local_focused {
                format!("{}█", self.form_tunnel.local_port)
            } else {
                self.form_tunnel.local_port.clone()
            };
            let local_val_style = if local_focused {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else if self.form_tunnel.local_port.is_empty() {
                Style::new().fg(Color::DarkGray)
            } else {
                Style::new().fg(Color::White).bold()
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        local_prefix,
                        if local_focused {
                            Style::new().fg(Color::Cyan).bold()
                        } else {
                            Style::new().fg(Color::Gray)
                        },
                    ),
                    Span::styled(format!(" {local_val} "), local_val_style),
                    Span::styled(
                        "   (本机监听并转发流量的端口)",
                        Style::new().fg(Color::DarkGray),
                    ),
                ])),
                local_line,
            );

            let remote_focused = self.form_tunnel.focus == FormTunnelFocus::RemoteTarget;
            let remote_prefix = if remote_focused {
                "▶ 远端目标服务: "
            } else {
                "  远端目标服务: "
            };
            let remote_val = if self.form_tunnel.remote.is_empty() {
                if remote_focused {
                    "█".to_string()
                } else {
                    "（留空默认 localhost:本地端口）".to_string()
                }
            } else if remote_focused {
                format!("{}█", self.form_tunnel.remote)
            } else {
                self.form_tunnel.remote.clone()
            };
            let remote_val_style = if remote_focused {
                Style::new().fg(Color::Black).bg(Color::Cyan).bold()
            } else if self.form_tunnel.remote.is_empty() {
                Style::new().fg(Color::DarkGray)
            } else {
                Style::new().fg(Color::White).bold()
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        remote_prefix,
                        if remote_focused {
                            Style::new().fg(Color::Cyan).bold()
                        } else {
                            Style::new().fg(Color::Gray)
                        },
                    ),
                    Span::styled(format!(" {remote_val} "), remote_val_style),
                    Span::styled(
                        "   (格式 host:port 或 纯端口)",
                        Style::new().fg(Color::DarkGray),
                    ),
                ])),
                remote_line,
            );

            // 远端服务列表
            let is_ports_focused = self.form_tunnel.focus == FormTunnelFocus::RemoteList;
            let ports_title = if self.pending_scan.is_some() {
                " ⚡ 远端可用服务 (🔍 正在探测中...) "
            } else if self.remote_ports.is_empty() {
                " ⚡ 远端可用服务 (未检测到监听服务 · 按 r 刷新) "
            } else {
                " ⚡ 远端可用服务 (回车一键转发 · 空格填入表单 · 按 r 刷新) "
            };
            let ports_border_style = if is_ports_focused {
                Style::new().fg(Color::Yellow).bold()
            } else {
                Style::new().fg(Color::DarkGray)
            };
            let ports_block = Block::new()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(ports_title)
                .title_style(if is_ports_focused {
                    Style::new().fg(Color::Yellow).bold()
                } else {
                    Style::new().fg(Color::Gray)
                })
                .border_style(ports_border_style);

            if self.remote_ports.is_empty() {
                let msg = if self.pending_scan.is_some() {
                    "  ⏳ 正在通过 SSH 会话执行端口探测 (ss / netstat)..."
                } else {
                    "  ○ 暂未检测到远端监听的 TCP 服务 (可在上方手动输入，或按 r 刷新探测)"
                };
                f.render_widget(
                    Paragraph::new(msg)
                        .style(Style::new().fg(Color::DarkGray))
                        .block(ports_block),
                    ports_section,
                );
            } else {
                let current_tunnels = self
                    .current_host()
                    .map(|h| h.tunnels.as_slice())
                    .unwrap_or(&[]);
                let rows: Vec<Row> = self
                    .remote_ports
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let is_selected_row = is_ports_focused && i == self.ports_selected;
                        let prefix = if is_selected_row { "▶ " } else { "  " };

                        let mapped = current_tunnels
                            .iter()
                            .find(|t| t.remote_port == p.port as u32);
                        let (status_text, status_style) = match mapped {
                            Some(t) => {
                                if t.enabled {
                                    (
                                        format!("● 已映射 (本地 {})", t.local_port),
                                        Style::new().fg(Color::Green),
                                    )
                                } else {
                                    (
                                        format!("○ 已映射但停用 (本地 {})", t.local_port),
                                        Style::new().fg(Color::Yellow),
                                    )
                                }
                            }
                            None => ("○ 未映射".to_string(), Style::new().fg(Color::DarkGray)),
                        };

                        let proc_name = if p.process.is_empty() {
                            "未知进程".to_string()
                        } else {
                            p.process.clone()
                        };

                        let port_text = format!("{}{}", prefix, p.port);
                        let port_style = if is_selected_row {
                            Style::new().fg(Color::Yellow).bold()
                        } else {
                            Style::new().fg(Color::Cyan)
                        };

                        Row::new(vec![
                            Cell::from(Span::styled(port_text, port_style)),
                            Cell::from(Span::styled(proc_name, Style::new().fg(Color::White))),
                            Cell::from(Span::styled(status_text, status_style)),
                        ])
                    })
                    .collect();

                let table = Table::new(
                    rows,
                    [
                        Constraint::Length(12),
                        Constraint::Length(28),
                        Constraint::Min(16),
                    ],
                )
                .header(
                    Row::new(vec!["  端口", "服务/进程名称", "当前状态"])
                        .style(Style::new().fg(Color::Gray).bold()),
                )
                .block(ports_block)
                .row_highlight_style(if is_ports_focused {
                    Style::new().fg(Color::Black).bg(Color::Yellow).bold()
                } else {
                    Style::new().fg(Color::White).bg(Color::DarkGray)
                });

                let mut state = TableState::new().with_selected(Some(self.ports_selected));
                f.render_stateful_widget(table, ports_section, &mut state);
            }

            // 底部提示
            let hint_line = match self.form_tunnel.focus {
                FormTunnelFocus::LocalPort | FormTunnelFocus::RemoteTarget => Line::from(vec![
                    Span::styled(" [Tab/Shift-Tab] ", Style::new().fg(Color::Yellow)),
                    Span::raw("切换输入/列表   "),
                    Span::styled(" [Enter] ", Style::new().fg(Color::Green)),
                    Span::raw("确认创建   "),
                    Span::styled(" [↓] ", Style::new().fg(Color::Cyan)),
                    Span::raw("快速选端口   "),
                    Span::styled(" [Esc] ", Style::new().fg(Color::Red)),
                    Span::raw("取消"),
                ]),
                FormTunnelFocus::RemoteList => Line::from(vec![
                    Span::styled(" [Enter] ", Style::new().fg(Color::Green).bold()),
                    Span::styled("⚡一键创建   ", Style::new().fg(Color::Green).bold()),
                    Span::styled(" [Space] ", Style::new().fg(Color::Cyan)),
                    Span::raw("填入表单修改   "),
                    Span::styled(" [↑/↓/j/k] ", Style::new().fg(Color::Yellow)),
                    Span::raw("选择   "),
                    Span::styled(" [r] ", Style::new().fg(Color::Magenta)),
                    Span::raw("刷新   "),
                    Span::styled(" [Tab/Esc] ", Style::new().fg(Color::Gray)),
                    Span::raw("返回输入/取消"),
                ]),
            };

            f.render_widget(
                Paragraph::new(hint_line)
                    .alignment(Alignment::Center)
                    .style(Style::new().fg(Color::DarkGray)),
                hint_section,
            );
        }
    }
}

/// TUI 入口
pub(crate) async fn run(
    cmd_tx: mpsc::Sender<Command>,
    event_rx: mpsc::UnboundedReceiver<TunnelEvent>,
) -> io::Result<()> {
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            std::io::stdout(),
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cmd_tx, event_rx);
    let res = app.run(&mut terminal).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    res
}
