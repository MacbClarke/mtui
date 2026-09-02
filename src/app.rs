//! TUI 界面：隧道列表视图 + 键盘交互（新增/删除/选择）+ 统一美观的新建隧道与端口发现弹窗。
//! 与 TunnelManager 解耦：指令走 mpsc，状态回报走快照事件。

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Constraint::{Length, Min};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, List, Paragraph, Row, Table, TableState,
};
use tokio::sync::{mpsc, oneshot};

use crate::tunnel::{Command, ConnectionStatus, Event as TunnelEvent, RemotePort, TunnelInfo};

/// 界面模式
enum Mode {
    /// 列表浏览
    List,
    /// 新增隧道表单（内嵌远端服务自动发现与快速选择）
    Input,
    /// 查看选中隧道的日志
    Log { port: u16, scroll: usize },
}

/// 新增表单焦点位置
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FormFocus {
    /// 本地端口输入
    LocalPort,
    /// 远端目标输入
    RemoteTarget,
    /// 远端发现服务列表
    RemoteList,
}

/// 新增表单状态
struct Form {
    focus: FormFocus,
    local_port: String,
    remote: String,
}

impl Form {
    fn new() -> Self {
        Self {
            focus: FormFocus::LocalPort,
            local_port: String::new(),
            remote: String::new(),
        }
    }

    /// 提交解析：返回 (本地端口, 远端 host, 远端端口)
    /// 规则：本地端口必填；远端留空 → localhost:本地端口；
    /// 只填数字 → localhost:该端口；完整 host:port 原样使用。
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
    tunnels: Vec<TunnelInfo>,
    selected: usize,
    mode: Mode,
    form: Form,
    /// SSH 连接状态
    conn_status: ConnectionStatus,
    /// 待发送到后台的命令（on_key 同步收集，主循环异步发送）
    pending_cmds: Vec<Command>,
    /// 挂起的命令回执（oneshot 无法跨 await 等待，在主循环轮询；带发起时间用于超时兜底）
    pending_reply: Option<(std::time::Instant, oneshot::Receiver<Result<(), String>>)>,
    /// 挂起的远端端口扫描回执
    pending_scan: Option<oneshot::Receiver<Vec<RemotePort>>>,
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
            tunnels: Vec::new(),
            selected: 0,
            mode: Mode::List,
            form: Form::new(),
            pending_cmds: Vec::new(),
            pending_reply: None,
            pending_scan: None,
            remote_ports: Vec::new(),
            ports_selected: 0,
            status: None,
            conn_status: ConnectionStatus::Connected,
            quit: false,
        }
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

            // 2. 后台快照
            while let Ok(ev) = self.event_rx.try_recv() {
                match ev {
                    TunnelEvent::State { status, tunnels } => {
                        self.conn_status = status;
                        self.tunnels = tunnels;
                        self.selected = self.selected.min(self.tunnels.len().saturating_sub(1));
                        if let Mode::Log { port, .. } = self.mode {
                            if !self.tunnels.iter().any(|t| t.local_port == port) {
                                self.mode = Mode::List;
                            }
                        }
                    }
                }
            }

            // 3. 发送待发命令（async 发送，不可在 on_key 里同步阻塞）
            for cmd in self.pending_cmds.drain(..) {
                if self.cmd_tx.send(cmd).await.is_err() {
                    self.status = Some(("后台任务已退出".into(), true));
                }
            }

            // 3.5 端口扫描回执
            if let Some(rx) = &mut self.pending_scan {
                if let Ok(ports) = rx.try_recv() {
                    self.remote_ports = ports;
                    if !self.remote_ports.is_empty() {
                        self.ports_selected =
                            self.ports_selected.min(self.remote_ports.len() - 1);
                    } else {
                        self.ports_selected = 0;
                    }
                    self.pending_scan = None;
                }
            }

            // 4. 命令回执（含超时兜底：后台忙碌/卡住时不至于永久显示“处理中”）
            if let Some((started, rx)) = &mut self.pending_reply {
                if let Ok(res) = rx.try_recv() {
                    match res {
                        Ok(()) => self.status = Some(("已成功创建隧道".into(), false)),
                        Err(e) => self.status = Some((e, true)),
                    }
                    self.pending_reply = None;
                } else if started.elapsed() > std::time::Duration::from_secs(10) {
                    self.status = Some(("后台命令超时（连接重连中？），请重试".into(), true));
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
                KeyCode::Char('a') => {
                    self.mode = Mode::Input;
                    self.form = Form::new();
                    self.status = None;
                    self.refresh_ports();
                }
                KeyCode::Char('p') => {
                    // 兼容习惯：直接打开新建弹窗并聚焦到远端服务列表
                    self.mode = Mode::Input;
                    self.form = Form::new();
                    self.form.focus = FormFocus::RemoteList;
                    self.status = None;
                    self.refresh_ports();
                }
                KeyCode::Char('d') | KeyCode::Delete => self.remove_selected(),
                KeyCode::Char('j') | KeyCode::Down => self.select(1),
                KeyCode::Char('k') | KeyCode::Up => self.select(-1),
                KeyCode::Char('l') => {
                    if let Some(t) = self.tunnels.get(self.selected) {
                        self.mode = Mode::Log {
                            port: t.local_port,
                            scroll: 0,
                        };
                        self.status = None;
                    }
                }
                _ => {}
            },
            Mode::Log { port, scroll } => {
                let mut new_scroll = scroll;
                let mut back = false;
                match key.code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        if let Some(t) = self.tunnels.iter().find(|t| t.local_port == port) {
                            new_scroll = (new_scroll + 1).min(t.log.len().saturating_sub(1));
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        new_scroll = new_scroll.saturating_sub(1);
                    }
                    KeyCode::Char('g') => new_scroll = 0,
                    KeyCode::Char('G') => {
                        if let Some(t) = self.tunnels.iter().find(|t| t.local_port == port) {
                            new_scroll = t.log.len().saturating_sub(1);
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
            Mode::Input => {
                let has_ports = !self.remote_ports.is_empty();
                match key.code {
                    KeyCode::Esc => {
                        self.mode = Mode::List;
                        self.status = None;
                    }
                    KeyCode::Tab => {
                        self.form.focus = match self.form.focus {
                            FormFocus::LocalPort => FormFocus::RemoteTarget,
                            FormFocus::RemoteTarget => {
                                if has_ports {
                                    FormFocus::RemoteList
                                } else {
                                    FormFocus::LocalPort
                                }
                            }
                            FormFocus::RemoteList => FormFocus::LocalPort,
                        };
                    }
                    KeyCode::BackTab => {
                        self.form.focus = match self.form.focus {
                            FormFocus::LocalPort => {
                                if has_ports {
                                    FormFocus::RemoteList
                                } else {
                                    FormFocus::RemoteTarget
                                }
                            }
                            FormFocus::RemoteTarget => FormFocus::LocalPort,
                            FormFocus::RemoteList => FormFocus::RemoteTarget,
                        };
                    }
                    KeyCode::Down => match self.form.focus {
                        FormFocus::LocalPort => self.form.focus = FormFocus::RemoteTarget,
                        FormFocus::RemoteTarget => {
                            if has_ports {
                                self.form.focus = FormFocus::RemoteList;
                            }
                        }
                        FormFocus::RemoteList => {
                            if has_ports {
                                self.ports_selected =
                                    (self.ports_selected + 1).min(self.remote_ports.len() - 1);
                            }
                        }
                    },
                    KeyCode::Up => match self.form.focus {
                        FormFocus::LocalPort => {}
                        FormFocus::RemoteTarget => self.form.focus = FormFocus::LocalPort,
                        FormFocus::RemoteList => {
                            if self.ports_selected == 0 {
                                self.form.focus = FormFocus::RemoteTarget;
                            } else {
                                self.ports_selected = self.ports_selected.saturating_sub(1);
                            }
                        }
                    },
                    KeyCode::Char('j') if self.form.focus == FormFocus::RemoteList => {
                        if has_ports {
                            self.ports_selected =
                                (self.ports_selected + 1).min(self.remote_ports.len() - 1);
                        }
                    }
                    KeyCode::Char('k') if self.form.focus == FormFocus::RemoteList => {
                        if self.ports_selected == 0 {
                            self.form.focus = FormFocus::RemoteTarget;
                        } else {
                            self.ports_selected = self.ports_selected.saturating_sub(1);
                        }
                    }
                    KeyCode::Char('r') | KeyCode::Char('R')
                        if self.form.focus == FormFocus::RemoteList =>
                    {
                        self.refresh_ports();
                    }
                    KeyCode::Char(' ') if self.form.focus == FormFocus::RemoteList => {
                        if let Some(rp) = self.remote_ports.get(self.ports_selected).cloned() {
                            self.fill_form_from_port(&rp);
                        }
                    }
                    KeyCode::Enter => match self.form.focus {
                        FormFocus::LocalPort => {
                            if self.form.local_port.trim().is_empty() {
                                if has_ports {
                                    self.form.focus = FormFocus::RemoteList;
                                } else {
                                    self.form.focus = FormFocus::RemoteTarget;
                                }
                            } else if self.form.remote.trim().is_empty() {
                                // 本地端口已填且远端留空 -> 直接以 localhost:本地端口 提交
                                self.submit_form();
                            } else {
                                self.submit_form();
                            }
                        }
                        FormFocus::RemoteTarget => {
                            self.submit_form();
                        }
                        FormFocus::RemoteList => {
                            if let Some(rp) = self.remote_ports.get(self.ports_selected).cloned() {
                                self.add_tunnel_from_port(&rp);
                            }
                        }
                    },
                    KeyCode::Backspace => match self.form.focus {
                        FormFocus::LocalPort => {
                            self.form.local_port.pop();
                        }
                        FormFocus::RemoteTarget => {
                            self.form.remote.pop();
                        }
                        FormFocus::RemoteList => {}
                    },
                    KeyCode::Char(c) => match self.form.focus {
                        FormFocus::LocalPort => {
                            if c.is_ascii_digit() {
                                self.form.local_port.push(c);
                            }
                        }
                        FormFocus::RemoteTarget => {
                            self.form.remote.push(c);
                        }
                        FormFocus::RemoteList => {}
                    },
                    _ => {}
                }
            }
        }
    }

    fn select(&mut self, delta: isize) {
        if self.tunnels.is_empty() {
            return;
        }
        let len = self.tunnels.len() as isize;
        self.selected = ((self.selected as isize + delta).rem_euclid(len)) as usize;
    }

    fn remove_selected(&mut self) {
        let Some(t) = self.tunnels.get(self.selected) else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::Remove {
            local_port: t.local_port,
            reply: tx,
        });
        self.pending_reply = Some((std::time::Instant::now(), rx));
        self.status = Some((format!("正在删除隧道 {}…", t.local_port), false));
    }

    /// 请求一次远端端口扫描
    fn refresh_ports(&mut self) {
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::ScanPorts { reply: tx });
        self.pending_scan = Some(rx);
    }

    /// 探测本地端口是否空闲（bind 测试，立即释放）
    fn port_free(port: u16) -> bool {
        std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
    }

    /// 从端口列表一键创建隧道：本地端口优先等于远端端口，被占用则向上递增寻找
    fn add_tunnel_from_port(&mut self, rp: &RemotePort) {
        let mut local = rp.port;
        while !Self::port_free(local) && local < 65535 {
            local += 1;
        }
        let (tx, rx) = oneshot::channel();
        self.pending_cmds.push(Command::Add {
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
            format!("正在添加隧道 {local} -> localhost:{} {hint}", rp.port),
            false,
        ));
    }

    /// 将选中的远端服务填入表单，供用户按需微调本地端口
    fn fill_form_from_port(&mut self, rp: &RemotePort) {
        let mut local = rp.port;
        while !Self::port_free(local) && local < 65535 {
            local += 1;
        }
        self.form.local_port = local.to_string();
        self.form.remote = format!("localhost:{}", rp.port);
        self.form.focus = FormFocus::LocalPort;
        if local != rp.port {
            self.status = Some((
                format!(
                    "已自动填入端口 {}（原本地端口已被占用，已推荐可用端口 {}）",
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

    fn submit_form(&mut self) {
        match self.form.parse() {
            Err(e) => {
                self.status = Some((e, true));
            }
            Ok((local_port, host, remote_port)) => {
                let (tx, rx) = oneshot::channel();
                self.pending_cmds.push(Command::Add {
                    local_port,
                    remote_host: host,
                    remote_port,
                    reply: tx,
                });
                self.pending_reply = Some((std::time::Instant::now(), rx));
                self.mode = Mode::List;
                self.status = Some((format!("正在添加隧道 {local_port}…"), false));
            }
        }
    }

    // ---------- 渲染 ----------

    /// 将字节/秒格式化为可读单位
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

    /// 将累计字节格式化为可读单位（无速率后缀）
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

    /// 连接状态横幅
    fn status_banner(&self) -> (String, Style) {
        match self.conn_status {
            ConnectionStatus::Connected => ("● 已连接".into(), Style::new().fg(Color::Green)),
            ConnectionStatus::Reconnecting(n) => (
                format!("◐ 重连中(第{n}次)…"),
                Style::new().fg(Color::Yellow).bold(),
            ),
            ConnectionStatus::Disconnected => {
                ("○ 已断开".into(), Style::new().fg(Color::Red).bold())
            }
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        // 居中弹窗区域计算
        fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
            let w = width.min(area.width.saturating_sub(2));
            let h = height.min(area.height.saturating_sub(2));
            let x = area.x + area.width.saturating_sub(w) / 2;
            let y = area.y + area.height.saturating_sub(h) / 2;
            Rect::new(x, y, w, h)
        }

        let [header, list, footer] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(f.area());

        // 标题栏：进程名 + 连接状态 + 状态消息
        let mut title = " mtui — SSH 动态隧道管理 ".to_string();
        let mut border_style = Style::default();
        let (banner, banner_style) = self.status_banner();
        border_style = border_style.patch(banner_style);
        title.push_str(&banner);
        if let Some((msg, is_err)) = &self.status {
            title.push_str("  ·  ");
            title.push_str(msg);
            border_style = if *is_err {
                Style::new().fg(Color::Red).bold()
            } else {
                Style::new().fg(Color::Green)
            };
        }
        f.render_widget(
            Block::new()
                .title(title)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style),
            header,
        );

        // 隧道列表（Log 模式下不渲染，避免与日志面板重叠）
        if !matches!(self.mode, Mode::Log { .. }) {
            let rows: Vec<Row> = self
                .tunnels
                .iter()
                .map(|t| {
                    Row::new(vec![
                        Cell::from(t.local_port.to_string()),
                        Cell::from(format!("{}:{}", t.remote_host, t.remote_port)),
                        Cell::from(t.connections.to_string()),
                        Cell::from(Self::fmt_rate(t.rx_rate)),
                        Cell::from(Self::fmt_rate(t.tx_rate)),
                        Cell::from(Self::fmt_bytes(t.rx_bytes)),
                        Cell::from(Self::fmt_bytes(t.tx_bytes)),
                    ])
                })
                .collect();
            let table = Table::new(
                rows,
                [
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
                    "本地端口", "远端目标", "连接", "↓速率", "↑速率", "↓累计", "↑累计",
                ])
                .style(Style::new().fg(Color::White).bold()),
            )
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" 活跃隧道 (Active Tunnels) "),
            )
            .row_highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan).bold());
            let mut state = ratatui::widgets::TableState::new()
                .with_selected(Some(self.selected));
            f.render_stateful_widget(table, list, &mut state);
        }

        // 底栏帮助 / 日志视图
        match self.mode {
            Mode::List => {
                let help = format!(
                    " [a]新建/发现  [d]删除  [l]日志  [↑/↓]选择  [q]退出    共 {} 条隧道",
                    self.tunnels.len()
                );
                f.render_widget(
                    Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
                    footer,
                );
            }
            Mode::Log { port, scroll } => {
                let tunnel: Option<&TunnelInfo> =
                    self.tunnels.iter().find(|t| t.local_port == port);
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
                            .title(format!(" 隧道 {port} 日志 ")),
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
            Mode::Input => {
                // 保持主底栏提示
                let help = format!(
                    " [a]新建/发现  [d]删除  [l]日志  [↑/↓]选择  [q]退出    共 {} 条隧道",
                    self.tunnels.len()
                );
                f.render_widget(
                    Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
                    footer,
                );

                // 居中弹窗：新建隧道 & 远端服务发现
                let popup = centered_rect(76, 18, f.area());
                f.render_widget(Clear, popup);

                let modal_block = Block::new()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" ➕ 新建 SSH 端口转发 / 隧道 ")
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

                // --- 1. 表单输入区 ---
                let [local_line, remote_line, _space] =
                    Layout::vertical([Length(1), Length(1), Length(1)]).areas(form_section);

                let local_focused = self.form.focus == FormFocus::LocalPort;
                let local_prefix = if local_focused {
                    "▶ 本地监听端口: "
                } else {
                    "  本地监听端口: "
                };
                let local_val = if self.form.local_port.is_empty() {
                    if local_focused {
                        "█".to_string()
                    } else {
                        "（必填，例如 8080）".to_string()
                    }
                } else if local_focused {
                    format!("{}█", self.form.local_port)
                } else {
                    self.form.local_port.clone()
                };
                let local_val_style = if local_focused {
                    Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                } else if self.form.local_port.is_empty() {
                    Style::new().fg(Color::DarkGray)
                } else {
                    Style::new().fg(Color::White).bold()
                };
                let local_widget = Paragraph::new(Line::from(vec![
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
                ]));
                f.render_widget(local_widget, local_line);

                let remote_focused = self.form.focus == FormFocus::RemoteTarget;
                let remote_prefix = if remote_focused {
                    "▶ 远端目标服务: "
                } else {
                    "  远端目标服务: "
                };
                let remote_val = if self.form.remote.is_empty() {
                    if remote_focused {
                        "█".to_string()
                    } else {
                        "（留空默认 localhost:本地端口）".to_string()
                    }
                } else if remote_focused {
                    format!("{}█", self.form.remote)
                } else {
                    self.form.remote.clone()
                };
                let remote_val_style = if remote_focused {
                    Style::new().fg(Color::Black).bg(Color::Cyan).bold()
                } else if self.form.remote.is_empty() {
                    Style::new().fg(Color::DarkGray)
                } else {
                    Style::new().fg(Color::White).bold()
                };
                let remote_widget = Paragraph::new(Line::from(vec![
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
                ]));
                f.render_widget(remote_widget, remote_line);

                // --- 2. 远端服务发现列表区 ---
                let is_ports_focused = self.form.focus == FormFocus::RemoteList;
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
                    let rows: Vec<Row> = self
                        .remote_ports
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            let is_selected_row =
                                is_ports_focused && i == self.ports_selected;
                            let prefix = if is_selected_row { "▶ " } else { "  " };

                            let mapped = self
                                .tunnels
                                .iter()
                                .find(|t| t.remote_port == p.port as u32);
                            let (status_text, status_style) = match mapped {
                                Some(t) => (
                                    format!("● 已映射 (本地 {})", t.local_port),
                                    Style::new().fg(Color::Green),
                                ),
                                None => {
                                    ("○ 未映射".to_string(), Style::new().fg(Color::DarkGray))
                                }
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
                                Cell::from(Span::styled(
                                    proc_name,
                                    Style::new().fg(Color::White),
                                )),
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

                    let mut state =
                        TableState::new().with_selected(Some(self.ports_selected));
                    f.render_stateful_widget(table, ports_section, &mut state);
                }

                // --- 3. 底部提示区 ---
                let hint_line = match self.form.focus {
                    FormFocus::LocalPort | FormFocus::RemoteTarget => Line::from(vec![
                        Span::styled(" [Tab/Shift-Tab] ", Style::new().fg(Color::Yellow)),
                        Span::raw("切换输入/列表   "),
                        Span::styled(" [Enter] ", Style::new().fg(Color::Green)),
                        Span::raw("确认创建   "),
                        Span::styled(" [↓] ", Style::new().fg(Color::Cyan)),
                        Span::raw("快速选端口   "),
                        Span::styled(" [Esc] ", Style::new().fg(Color::Red)),
                        Span::raw("取消"),
                    ]),
                    FormFocus::RemoteList => Line::from(vec![
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
}

/// TUI 入口：初始化终端、运行主循环、恢复终端
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

    // 崩溃时恢复终端（手动初始化无 ratatui 的自动 panic hook）
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ =
            execute!(std::io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
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
    execute!(terminal.backend_mut(), LeaveAlternateScreen, crossterm::cursor::Show)?;
    res
}
