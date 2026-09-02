//! TUI 界面：隧道列表视图 + 键盘交互（新增/删除/选择）+ 输入表单。
//! 与 TunnelManager 解耦：指令走 mpsc，状态回报走快照事件。

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Constraint::{Length, Min};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use tokio::sync::{mpsc, oneshot};

use crate::tunnel::{Command, ConnectionStatus, Event as TunnelEvent, TunnelInfo};

/// 界面模式
enum Mode {
    /// 列表浏览
    List,
    /// 新增隧道表单
    Input,
}

/// 新增表单：两个字段（本地端口 / 远端 host:port）
struct Form {
    field: usize,
    local_port: String,
    remote: String,
}

impl Form {
    fn new() -> Self {
        Self {
            field: 0,
            local_port: String::new(),
            remote: String::new(),
        }
    }

    fn current(&mut self) -> &mut String {
        if self.field == 0 {
            &mut self.local_port
        } else {
            &mut self.remote
        }
    }

    /// 提交解析：返回 (本地端口, 远端 host, 远端端口)
    fn parse(&self) -> Result<(u16, String, u32), String> {
        let local_port: u16 = self
            .local_port
            .trim()
            .parse()
            .map_err(|_| format!("本地端口格式错误：{}", self.local_port.trim()))?;
        let (host, port) = self
            .remote
            .trim()
            .split_once(':')
            .ok_or_else(|| format!("远端目标格式应为 host:port：{}", self.remote.trim()))?;
        let remote_port: u32 = port
            .parse()
            .map_err(|_| format!("远端端口格式错误：{port}"))?;
        Ok((local_port, host.to_string(), remote_port))
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
    /// 挂起的命令回执（oneshot 无法跨 await 等待，在主循环轮询）
    pending_reply: Option<oneshot::Receiver<Result<(), String>>>,
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
                    }
                }
            }

            // 3. 发送待发命令（async 发送，不可在 on_key 里同步阻塞）
            for cmd in self.pending_cmds.drain(..) {
                if self.cmd_tx.send(cmd).await.is_err() {
                    self.status = Some(("后台任务已退出".into(), true));
                }
            }

            // 4. 命令回执
            if let Some(rx) = &mut self.pending_reply {
                if let Ok(res) = rx.try_recv() {
                    match res {
                        Ok(()) => self.status = Some(("已添加隧道".into(), false)),
                        Err(e) => self.status = Some((e, true)),
                    }
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
                }
                KeyCode::Char('d') | KeyCode::Delete => self.remove_selected(),
                KeyCode::Char('j') | KeyCode::Down => self.select(1),
                KeyCode::Char('k') | KeyCode::Up => self.select(-1),
                _ => {}
            },
            Mode::Input => match key.code {
                KeyCode::Char(c) => self.form.current().push(c),
                KeyCode::Backspace => {
                    self.form.current().pop();
                }
                KeyCode::Tab => self.form.field = 1 - self.form.field,
                KeyCode::Enter => {
                    if self.form.field == 0 {
                        self.form.field = 1;
                    } else {
                        self.submit_form();
                    }
                }
                KeyCode::Esc => {
                    self.mode = Mode::List;
                    self.status = None;
                }
                _ => {}
            },
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
        self.pending_reply = Some(rx);
        self.status = Some((format!("正在删除隧道 {}…", t.local_port), false));
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
                self.pending_reply = Some(rx);
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
            ConnectionStatus::Disconnected => ("○ 已断开".into(), Style::new().fg(Color::Red).bold()),
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let [header, list, footer] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(f.area());

        // 标题栏：进程名 + 连接状态 + 状态消息
        let mut title = " mtui — SSH 隧道 ".to_string();
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
                .border_style(border_style),
            header,
        );

        // 隧道列表
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
        .header(Row::new(vec![
            "本地端口", "远端目标", "连接", "↓速率", "↑速率", "↓累计", "↑累计",
        ]))
        .block(Block::new().borders(Borders::ALL).title(" 隧道 "))
        .row_highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan).bold());
        let mut state = ratatui::widgets::TableState::new()
            .with_selected(Some(self.selected));
        f.render_stateful_widget(table, list, &mut state);

        // 底栏：帮助 / 输入表单
        match self.mode {
            Mode::List => {
                let help = format!(
                    " [a]新增  [d]删除  [↑/↓]选择  [q]退出    共 {} 条隧道",
                    self.tunnels.len()
                );
                f.render_widget(
                    Paragraph::new(help).style(Style::new().fg(Color::DarkGray)),
                    footer,
                );
            }
            Mode::Input => {
                let local_style = if self.form.field == 0 {
                    Style::new().fg(Color::Cyan).bold()
                } else {
                    Style::new().fg(Color::DarkGray)
                };
                let remote_style = if self.form.field == 1 {
                    Style::new().fg(Color::Cyan).bold()
                } else {
                    Style::new().fg(Color::DarkGray)
                };
                let line = Line::from(vec![
                    Span::styled(" 本地端口: ", Style::new().fg(Color::Gray)),
                    Span::styled(format!("[{}]", self.form.local_port), local_style),
                    Span::styled("  远端目标: ", Style::new().fg(Color::Gray)),
                    Span::styled(format!("[{}]", self.form.remote), remote_style),
                    Span::styled("  [Tab]切换 [Enter]提交 [Esc]取消", Style::new().fg(Color::DarkGray)),
                ]);
                f.render_widget(
                    Paragraph::new(line).block(Block::default()),
                    footer,
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
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    // 崩溃时恢复终端（手动初始化无 ratatui 的自动 panic hook）
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
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