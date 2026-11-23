mod diagnostics;
mod grant;
mod pages;
mod settings;
mod theme;
mod view;

use crate::host;
use anyhow::{Result, ensure};
use folderspan_headless::{
    access::{Access, Credentials, DirectoryGrant, Feature},
    config::Launch,
    instance_lock::LockedProfile,
};
use grant::{GrantFlow, GrantFocus};
use pages::{Action, Row};
use ratatui::crossterm::{
    event::{
        self, DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste, EnableFocusChange,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
    },
    execute,
};
use settings::Form;
use std::{
    io::stdout,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum MenuAction {
    Open(Page),
    Export,
    Quit,
}

struct MenuItem {
    key: char,
    label: &'static str,
    help: &'static str,
    action: MenuAction,
}

const MENU: [MenuItem; 7] = [
    MenuItem {
        key: '1',
        label: "服务启停",
        help: "启动、停止或重启由本窗口启动的服务。",
        action: MenuAction::Open(Page::Service),
    },
    MenuItem {
        key: '2',
        label: "部署配置",
        help: "选择数据目录，编辑监听地址、端口、Web 资源目录和允许的 Origin。",
        action: MenuAction::Open(Page::Settings),
    },
    MenuItem {
        key: '3',
        label: "服务状态",
        help: "查看服务状态、监听端口和数据目录。",
        action: MenuAction::Open(Page::Status),
    },
    MenuItem {
        key: '4',
        label: "运行诊断",
        help: "检查端口占用、TLS 证书和 Web 界面资源。",
        action: MenuAction::Open(Page::Diagnostics),
    },
    MenuItem {
        key: '5',
        label: "导出诊断摘要",
        help: "生成最新诊断摘要，保存到你指定的文件。",
        action: MenuAction::Export,
    },
    MenuItem {
        key: '6',
        label: "访问控制",
        help: "管理 Web 登录密钥、目录读写权限和功能授权。",
        action: MenuAction::Open(Page::Keys),
    },
    MenuItem {
        key: '0',
        label: "退出",
        help: "关闭管理台。如果本窗口启动了服务，会先请你确认是否停机。",
        action: MenuAction::Quit,
    },
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Menu,
    Service,
    Settings,
    Status,
    Diagnostics,
    Keys,
    KeyActions,
    Grant,
}

enum Input {
    DataDirectory,
    Export,
    Name,
    Directory,
}

enum Confirm {
    Stop,
    Restart,
    Quit,
    Rotate(String),
    Revoke(String),
    DiscardSettings,
    DiscardPermissions,
    SwitchProfile(PathBuf),
}

enum Dialog {
    Input {
        title: &'static str,
        action: Input,
        editor: TextEdit,
    },
    Confirm {
        title: String,
        action: Confirm,
        selected: usize,
    },
    Secret(Zeroizing<String>),
    Details {
        title: String,
        text: String,
        scroll: u16,
    },
}

const CONFIRM_OPTIONS: [&str; 2] = ["确认", "取消"];

struct TextEdit {
    value: String,
    cursor: usize,
    selected_all: bool,
}

impl TextEdit {
    fn new(value: String) -> Self {
        Self {
            cursor: value.len(),
            value,
            selected_all: false,
        }
    }

    fn delete_selection(&mut self) -> bool {
        if std::mem::take(&mut self.selected_all) {
            self.value.clear();
            self.cursor = 0;
            return true;
        }
        false
    }

    fn paste(&mut self, text: &str) {
        let existing_len = if self.selected_all {
            0
        } else {
            self.value.len()
        };
        let mut available = 8192usize.saturating_sub(existing_len);
        let text: String = text
            .chars()
            .filter(|c| !c.is_control())
            .take_while(|c| {
                let fits = c.len_utf8() <= available;
                available = available.saturating_sub(c.len_utf8());
                fits
            })
            .collect();
        if !text.is_empty() {
            self.delete_selection();
            self.value.insert_str(self.cursor, &text);
            self.cursor += text.len();
        }
    }

    fn key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if key.code == KeyCode::Char('a') {
                self.selected_all = true;
            }
            return;
        }
        let previous = || {
            self.value[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i)
        };
        match key.code {
            KeyCode::Char(c) => self.paste(c.encode_utf8(&mut [0; 4])),
            KeyCode::Left => {
                self.cursor = if self.selected_all { 0 } else { previous() };
                self.selected_all = false;
            }
            KeyCode::Right => {
                self.cursor = if self.selected_all {
                    self.value.len()
                } else {
                    self.cursor
                        + self.value[self.cursor..]
                            .chars()
                            .next()
                            .map_or(0, char::len_utf8)
                };
                self.selected_all = false;
            }
            KeyCode::Home | KeyCode::End => {
                self.cursor = if key.code == KeyCode::Home {
                    0
                } else {
                    self.value.len()
                };
                self.selected_all = false;
            }
            KeyCode::Backspace => {
                if !self.delete_selection() && self.cursor != 0 {
                    let start = self.value[..self.cursor]
                        .char_indices()
                        .next_back()
                        .unwrap()
                        .0;
                    self.value.drain(start..self.cursor);
                    self.cursor = start;
                }
            }
            KeyCode::Delete => {
                if !self.delete_selection() && self.cursor < self.value.len() {
                    self.value.remove(self.cursor);
                }
            }
            _ => {}
        }
    }
}

struct Draft {
    id: Option<String>,
    original: (String, Access),
    name: String,
    full: bool,
    directories: Vec<DirectoryGrant>,
    features: std::collections::BTreeSet<Feature>,
}

impl Draft {
    fn new(key: Option<&folderspan_headless::access::Key>, first: bool) -> Self {
        let access = key.map(|key| key.access.clone()).unwrap_or_else(|| {
            if first {
                Access::Full
            } else {
                Access::Scoped {
                    features: Default::default(),
                    directories: Vec::new(),
                }
            }
        });
        let name = key.map(|key| key.name.clone()).unwrap_or_default();
        let original = (name.clone(), access.clone());
        let (full, features, directories) = match access {
            Access::Full => (true, Default::default(), Vec::new()),
            Access::Scoped {
                features,
                directories,
            } => (false, features, directories),
        };
        Self {
            id: key.map(|key| key.id.clone()),
            original,
            name,
            full,
            features,
            directories,
        }
    }

    fn access(&self) -> Access {
        if self.full {
            Access::Full
        } else {
            Access::Scoped {
                features: self.features.clone(),
                directories: self.directories.clone(),
            }
        }
    }

    fn dirty(&self) -> bool {
        self.name != self.original.0 || self.access() != self.original.1
    }
}

struct Service {
    cancel: CancellationToken,
    ready: Receiver<SocketAddr>,
    address: Option<SocketAddr>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl Service {
    fn start(launch: Launch) -> Result<Self> {
        let cancel = CancellationToken::new();
        let (ready, receiver) = mpsc::channel();
        let stop = cancel.clone();
        let worker = thread::Builder::new()
            .name("headless-service".into())
            .spawn(move || {
                host::run(launch, stop, false, |address| {
                    let _ = ready.send(address);
                })
            })?;
        Ok(Self {
            cancel,
            ready: receiver,
            address: None,
            worker: Some(worker),
        })
    }

    fn join(&mut self) -> Result<()> {
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("service worker stopped unexpectedly"))?
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Console<'a> {
    launch: Launch,
    runtime: &'a Runtime,
    page: Page,
    service: Option<Service>,
    restart: bool,
    quitting: bool,
    status: Option<diagnostics::Check>,
    report: diagnostics::Report,
    notice: String,
    has_error: bool,
    cursor: usize,
    menu: usize,
    form: Option<Form>,
    keys: Option<Credentials>,
    selected: usize,
    draft: Option<Draft>,
    grant: GrantFlow,
    dialog: Option<Dialog>,
}

impl<'a> Console<'a> {
    fn new(launch: Launch, runtime: &'a Runtime) -> Self {
        Self {
            launch,
            runtime,
            page: Page::Menu,
            service: None,
            restart: false,
            quitting: false,
            status: None,
            report: diagnostics::Report::default(),
            notice: String::new(),
            has_error: false,
            cursor: 0,
            menu: 0,
            form: None,
            keys: None,
            selected: 0,
            draft: None,
            grant: GrantFlow::default(),
            dialog: None,
        }
    }

    fn tick(&mut self) -> Result<()> {
        let Some(service) = &mut self.service else {
            return Ok(());
        };
        if let Ok(address) = service.ready.try_recv() {
            service.address = Some(address);
        }
        if service
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            let mut service = self.service.take().unwrap();
            match service.join() {
                Ok(()) if std::mem::take(&mut self.restart) => self.start()?,
                Ok(()) => {
                    self.has_error = false;
                    self.notice = "服务已停止".into();
                }
                Err(error) => {
                    self.restart = false;
                    self.error(error);
                }
            }
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        ensure!(self.service.is_none(), "This TUI already owns a service");
        self.service = Some(Service::start(self.launch.clone())?);
        self.notice = "正在启动服务…".into();
        Ok(())
    }

    fn service_state(&self) -> String {
        match &self.service {
            Some(service) if service.cancel.is_cancelled() => "正在停止服务".into(),
            Some(service) => match service.address {
                Some(address) => {
                    let endpoint = host::local_endpoint(address);
                    format!(
                        "服务状态：本管理台已启动\n监听地址：{address}\nWeb: http://{endpoint} / https://{endpoint}"
                    )
                }
                None => "正在启动服务".into(),
            },
            None => "本管理台尚未启动服务".into(),
        }
    }

    fn service_state_summary(&self) -> &'static str {
        match &self.service {
            Some(service) if service.cancel.is_cancelled() => "正在停止",
            Some(service) if service.address.is_some() => "本窗口运行中",
            Some(_) => "正在启动",
            None => "本窗口未启动",
        }
    }

    fn refresh_diagnostics(&mut self) {
        let own = self.service.as_ref().and_then(|service| service.address);
        let state = self.service_state();
        self.report = self.runtime.block_on(diagnostics::report(
            &self.launch,
            own,
            self.service.is_some(),
            &state,
        ));
    }

    fn refresh_status(&mut self) {
        let own = self.service.as_ref().and_then(|service| service.address);
        self.status = Some(
            self.runtime
                .block_on(diagnostics::endpoint(&self.launch, own)),
        );
    }

    fn reload_keys(&mut self) -> Result<()> {
        let credentials = Credentials::load(&self.launch.data_dir)?;
        self.selected = self
            .selected
            .min(credentials.keys().len().saturating_sub(1));
        self.keys = Some(credentials);
        Ok(())
    }

    fn select_page(&mut self, page: Page) {
        self.page = page;
        self.notice.clear();
        self.has_error = false;
        self.cursor = 0;
    }

    fn error(&mut self, error: anyhow::Error) {
        self.has_error = true;
        self.notice = format!("{error:#}");
    }

    fn editable(&self) -> Result<()> {
        ensure!(self.service.is_none(), "请先停止服务，再保存配置或密钥变更");
        Ok(())
    }

    fn mutate_keys<T>(&mut self, edit: impl FnOnce(&mut Credentials) -> Result<T>) -> Result<T> {
        self.editable()?;
        let profile = LockedProfile::acquire(&self.launch.data_dir)?;
        let mut credentials = Credentials::load(&profile.data_dir)?;
        let value = edit(&mut credentials)?;
        credentials.save(&profile.data_dir)?;
        self.selected = self
            .selected
            .min(credentials.keys().len().saturating_sub(1));
        self.keys = Some(credentials);
        Ok(value)
    }

    fn prompt(&mut self, title: &'static str, action: Input, value: String) {
        self.dialog = Some(Dialog::Input {
            title,
            action,
            editor: TextEdit::new(value),
        });
    }

    fn confirm(&mut self, title: impl Into<String>, action: Confirm) {
        let selected = usize::from(matches!(
            action,
            Confirm::Rotate(_) | Confirm::Revoke(_) | Confirm::DiscardPermissions
        ));
        self.dialog = Some(Dialog::Confirm {
            title: title.into(),
            action,
            selected,
        });
    }

    fn quit(&mut self) {
        if self.service.is_some() {
            self.confirm("停止服务并退出？", Confirm::Quit);
        } else if self
            .form
            .as_ref()
            .is_some_and(|form| form.dirty() || form.editor.is_some())
            || self.draft.as_ref().is_some_and(Draft::dirty)
        {
            self.confirm("放弃未保存的修改并退出？", Confirm::Quit);
        } else {
            self.quitting = true;
        }
    }

    fn save_input(&mut self, action: &Input, value: &str) -> Result<()> {
        match action {
            Input::DataDirectory => {
                self.editable()?;
                ensure!(!value.is_empty(), "请输入数据目录");
                let path = std::path::absolute(value)?;
                if path != self.launch.data_dir {
                    if self.form.as_ref().is_some_and(Form::dirty) {
                        self.confirm(
                            "放弃未保存的配置并切换数据目录？",
                            Confirm::SwitchProfile(path),
                        );
                    } else {
                        self.switch_profile(path)?;
                    }
                }
            }
            Input::Name => self.draft.as_mut().unwrap().name = value.to_owned(),
            Input::Directory => {
                let path = PathBuf::from(value);
                ensure!(
                    path.is_absolute() && path.is_dir(),
                    "请输入已存在目录的绝对路径"
                );
                let path = folderspan_headless::config::canonical_path(&path)?;
                let draft = self.draft.as_mut().unwrap();
                ensure!(
                    !draft.directories.iter().any(|grant| grant.path == path),
                    "此目录已在授权列表中"
                );
                self.grant.select(draft.directories.len());
                draft
                    .directories
                    .push(DirectoryGrant { path, write: false });
            }
            Input::Export => {
                ensure!(!value.is_empty(), "请输入诊断摘要的保存路径");
                diagnostics::export(Path::new(value), &self.report.summary())?;
                self.notice = format!("诊断摘要已保存到 {value}");
            }
        }
        Ok(())
    }

    fn switch_profile(&mut self, path: PathBuf) -> Result<()> {
        let mut launch = self.launch.clone();
        launch.data_dir = path;
        let form = Form::load(&launch)?;
        self.launch = launch;
        self.form = Some(form);
        self.keys = None;
        self.selected = 0;
        self.notice = "已切换数据目录".into();
        Ok(())
    }

    fn confirm_action(&mut self, action: Confirm) -> Result<()> {
        match action {
            Confirm::Stop | Confirm::Restart | Confirm::Quit => {
                self.quitting = matches!(action, Confirm::Quit);
                self.restart = matches!(action, Confirm::Restart);
                if let Some(service) = &self.service {
                    service.cancel.cancel();
                }
            }
            Confirm::Rotate(id) => {
                let secret = self.mutate_keys(|credentials| credentials.rotate(&id))?;
                self.dialog = Some(Dialog::Secret(secret));
            }
            Confirm::Revoke(id) => {
                self.mutate_keys(|credentials| credentials.revoke(&id))?;
                self.back_to_keys();
                self.notice = "所选密钥已撤销".into();
            }
            Confirm::DiscardSettings => self.leave_settings(),
            Confirm::DiscardPermissions => self.leave_permissions(),
            Confirm::SwitchProfile(path) => self.switch_profile(path)?,
        }
        Ok(())
    }

    fn dialog_key(&mut self, dialog: Dialog, key: KeyEvent) -> Result<()> {
        match dialog {
            Dialog::Secret(secret) => match key.code {
                KeyCode::Enter | KeyCode::Esc => {}
                _ => self.dialog = Some(Dialog::Secret(secret)),
            },
            Dialog::Confirm {
                title,
                action,
                mut selected,
            } => match key.code {
                KeyCode::Enter if selected == 0 => self.confirm_action(action)?,
                KeyCode::Char('y') => self.confirm_action(action)?,
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('n') => {}
                _ => {
                    move_focus(key.code, &mut selected, CONFIRM_OPTIONS.len());
                    self.dialog = Some(Dialog::Confirm {
                        title,
                        action,
                        selected,
                    });
                }
            },
            Dialog::Details {
                title,
                text,
                mut scroll,
            } => {
                match key.code {
                    KeyCode::Enter | KeyCode::Esc => return Ok(()),
                    KeyCode::Up => scroll = scroll.saturating_sub(1),
                    KeyCode::Down => {
                        scroll = scroll
                            .saturating_add(1)
                            .min(text.chars().count().min(u16::MAX as usize) as u16)
                    }
                    _ => {}
                }
                self.dialog = Some(Dialog::Details {
                    title,
                    text,
                    scroll,
                });
            }
            Dialog::Input {
                title,
                action,
                mut editor,
            } => {
                match key.code {
                    KeyCode::Esc => return Ok(()),
                    KeyCode::Enter => {
                        if let Err(error) = self.save_input(&action, &editor.value) {
                            self.dialog = Some(Dialog::Input {
                                title,
                                action,
                                editor,
                            });
                            return Err(error);
                        }
                        return Ok(());
                    }
                    _ => editor.key(key),
                }
                self.dialog = Some(Dialog::Input {
                    title,
                    action,
                    editor,
                });
            }
        }
        Ok(())
    }

    fn save_draft(&mut self) -> Result<()> {
        let draft = self.draft.as_ref().unwrap();
        let (id, original, name, access) = (
            draft.id.clone(),
            draft.original.clone(),
            draft.name.clone(),
            draft.access(),
        );
        let secret = self.mutate_keys(|credentials| {
            if let Some(id) = id {
                let current = credentials
                    .keys()
                    .iter()
                    .find(|key| key.id == id)
                    .map(|key| (key.name.clone(), key.access.clone()));
                ensure!(
                    Some(original) == current,
                    "密钥已在其他窗口修改。请重新打开权限编辑。"
                );
                credentials.edit(&id, name, access)?;
                Ok(None)
            } else {
                credentials.add(name, access).map(Some)
            }
        })?;
        if secret.is_some() {
            self.selected = self.keys().len().saturating_sub(1);
        }
        self.draft = None;
        self.back_to_keys();
        self.notice = "密钥和权限已保存".into();
        self.dialog = secret.map(Dialog::Secret);
        Ok(())
    }

    fn back_to_keys(&mut self) {
        self.select_page(Page::Keys);
        if !self.keys().is_empty() {
            self.cursor = self.selected + 1;
        }
    }

    fn leave_permissions(&mut self) {
        let existing = self.draft.take().is_some_and(|draft| draft.id.is_some());
        if existing {
            self.select_page(Page::KeyActions);
            self.cursor = 1;
        } else {
            self.select_page(Page::Keys);
        }
    }

    fn request_leave_permissions(&mut self) {
        if self.draft.as_ref().is_some_and(Draft::dirty) {
            self.confirm("放弃未保存的权限修改？", Confirm::DiscardPermissions);
        } else {
            self.leave_permissions();
        }
    }

    fn show_details(&mut self, row: Row) {
        let text = row.description();
        self.dialog = Some(Dialog::Details {
            title: row.label,
            text,
            scroll: 0,
        });
    }

    fn run_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Inspect => unreachable!("details are handled by the selected row"),
            Action::Start => self.start()?,
            Action::Stop => self.confirm("停止服务？", Confirm::Stop),
            Action::Restart => self.confirm("重启服务？", Confirm::Restart),
            Action::RefreshStatus => self.refresh_status(),
            Action::RefreshDiagnostics => self.refresh_diagnostics(),
            Action::Export => self.prompt(
                "导出诊断摘要",
                Input::Export,
                "folderspan-diagnostics.txt".into(),
            ),
            Action::MainMenu => self.select_page(Page::Menu),
            Action::Keys => self.back_to_keys(),
            Action::Key(index) => {
                self.selected = index;
                self.select_page(Page::KeyActions);
                self.cursor = 1;
            }
            Action::NewKey => {
                self.editable()?;
                self.draft = Some(Draft::new(None, self.keys().is_empty()));
                self.grant = GrantFlow::default();
                self.select_page(Page::Grant);
            }
            Action::EditKey => {
                let key = self.keys().get(self.selected);
                ensure!(key.is_some(), "请选择一把密钥");
                self.draft = Some(Draft::new(key, false));
                self.grant = GrantFlow::default();
                self.select_page(Page::Grant);
            }
            Action::ResetKey | Action::RevokeKey => {
                self.editable()?;
                let key = self.keys().get(self.selected);
                let key = key.ok_or_else(|| anyhow::anyhow!("请选择一把密钥"))?;
                let (id, name) = (key.id.clone(), key.name.clone());
                if matches!(action, Action::ResetKey) {
                    self.confirm(
                        format!("重置后旧密钥会失效。继续重置「{name}」？"),
                        Confirm::Rotate(id),
                    );
                } else {
                    self.confirm(
                        format!("撤销后此密钥无法登录。继续撤销「{name}」？"),
                        Confirm::Revoke(id),
                    );
                }
            }
            Action::EditName => {
                self.editable()?;
                let name = self.draft.as_ref().unwrap().name.clone();
                self.prompt("密钥名称", Input::Name, name);
            }
            Action::ToggleMode => {
                self.editable()?;
                let draft = self.draft.as_mut().unwrap();
                draft.full = !draft.full;
            }
            Action::ToggleFeature(feature) => {
                self.editable()?;
                let features = &mut self.draft.as_mut().unwrap().features;
                if !features.remove(&feature) {
                    features.insert(feature);
                }
            }
            Action::Directory(index) => {
                let grant = &self.draft.as_ref().unwrap().directories[index];
                self.editable()?;
                self.grant.focus = GrantFocus::Directory(usize::from(grant.write));
            }
            Action::AddDirectory => {
                self.editable()?;
                self.prompt("添加授权目录", Input::Directory, String::new());
            }
        }
        Ok(())
    }

    fn page_key(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Esc {
            match self.page {
                Page::KeyActions => self.back_to_keys(),
                _ => self.select_page(Page::Menu),
            }
            return Ok(());
        }
        let rows = self.screen().rows;
        self.cursor = self.cursor.min(rows.len() - 1);
        if move_focus(key.code, &mut self.cursor, rows.len()) {
            return Ok(());
        }
        if key.code == KeyCode::Enter {
            let row = rows.into_iter().nth(self.cursor).unwrap();
            if matches!(row.action, Action::Inspect) {
                self.show_details(row);
                return Ok(());
            }
            return self.run_action(row.action);
        }
        let shortcut = match (self.page, key.code) {
            (Page::Service, KeyCode::Char('s')) => Some(Action::Start),
            (Page::Service, KeyCode::Char('x')) if self.service.is_some() => Some(Action::Stop),
            (Page::Service, KeyCode::Char('r')) if self.service.is_some() => Some(Action::Restart),
            (Page::Status, KeyCode::Char('r')) => Some(Action::RefreshStatus),
            (Page::Diagnostics, KeyCode::Char('r')) => Some(Action::RefreshDiagnostics),
            (Page::Diagnostics, KeyCode::Char('e')) => Some(Action::Export),
            _ => None,
        };
        if let Some(action) = shortcut {
            self.run_action(action)?;
        }
        Ok(())
    }

    fn menu_action(&mut self, action: MenuAction) -> Result<()> {
        match action {
            MenuAction::Quit => self.quit(),
            MenuAction::Export => {
                self.select_page(Page::Diagnostics);
                self.refresh_diagnostics();
                self.prompt(
                    "导出诊断摘要",
                    Input::Export,
                    "folderspan-diagnostics.txt".into(),
                );
            }
            MenuAction::Open(page) => {
                if page == Page::Settings {
                    self.form = Some(Form::load(&self.launch)?);
                }
                self.select_page(page);
                match page {
                    Page::Status => self.refresh_status(),
                    Page::Diagnostics => self.refresh_diagnostics(),
                    Page::Keys => {
                        self.reload_keys()?;
                        self.back_to_keys();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn leave_settings(&mut self) {
        self.form = None;
        self.select_page(Page::Menu);
    }

    fn save_settings(&mut self) -> Result<()> {
        self.editable()?;
        let form = self.form.as_mut().expect("deployment settings are open");
        if form.dirty() {
            form.save(&self.launch)?;
            self.notice = "部署配置已保存".into();
        } else {
            self.notice = "没有需要保存的修改".into();
        }
        Ok(())
    }

    fn select_settings_row(&mut self) -> Result<()> {
        let form = self.form.as_mut().expect("deployment settings are open");
        if form.selected == Form::SAVE {
            return self.save_settings();
        }
        self.editable()?;
        if let Some(field) = self.form.as_ref().and_then(Form::field) {
            self.form.as_mut().unwrap().begin(field);
        } else {
            self.prompt(
                "切换数据目录",
                Input::DataDirectory,
                self.launch.data_dir.display().to_string(),
            );
        }
        Ok(())
    }

    fn settings_key(&mut self, key: KeyEvent) -> Result<()> {
        let save = key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL);
        let form = self.form.as_mut().expect("deployment settings are open");
        if let Some(editor) = &mut form.editor {
            match key.code {
                KeyCode::Esc => form.editor = None,
                KeyCode::Enter => form.finish()?,
                KeyCode::Tab | KeyCode::BackTab => {
                    form.finish()?;
                    form.move_by(if key.code == KeyCode::Tab { 1 } else { -1 });
                }
                _ if save => {
                    form.finish()?;
                    self.save_settings()?;
                }
                _ => editor.key(key),
            }
            return Ok(());
        }
        match key.code {
            KeyCode::Enter => self.select_settings_row()?,
            KeyCode::Up | KeyCode::BackTab => form.move_by(-1),
            KeyCode::Down | KeyCode::Tab => form.move_by(1),
            KeyCode::Home => form.selected = 0,
            KeyCode::End => form.selected = Form::SAVE,
            KeyCode::Esc => {
                if form.dirty() {
                    self.confirm("放弃未保存的部署配置？", Confirm::DiscardSettings);
                } else {
                    self.leave_settings();
                }
            }
            _ if save => self.save_settings()?,
            KeyCode::Char(letter @ ('d' | 'a' | 'p' | 'w' | 'o')) if key.modifiers.is_empty() => {
                form.selected = "dapwo".find(letter).unwrap();
                self.select_settings_row()?;
            }
            _ => {}
        }
        Ok(())
    }

    fn key(&mut self, key: KeyEvent) -> Result<()> {
        if key.kind == KeyEventKind::Release
            || key.kind == KeyEventKind::Repeat && key.code == KeyCode::Enter
            || self.quitting
        {
            return Ok(());
        }
        self.notice.clear();
        self.has_error = false;
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.dialog = None;
            self.quit();
            return Ok(());
        }
        if let Some(dialog) = self.dialog.take() {
            return self.dialog_key(dialog, key);
        }
        let code = key.code;
        if self.page == Page::Settings {
            return self.settings_key(key);
        }
        if self.page == Page::Grant {
            return self.grant_key(key);
        }
        if self.page != Page::Menu {
            return self.page_key(key);
        }
        if move_focus(code, &mut self.menu, MENU.len()) {
            return Ok(());
        }
        match code {
            KeyCode::Enter => self.menu_action(MENU[self.menu].action)?,
            KeyCode::Char('q') => self.quit(),
            KeyCode::Char(c) => {
                if let Some(index) = MENU.iter().position(|item| item.key == c) {
                    self.menu = index;
                    self.menu_action(MENU[index].action)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn paste(&mut self, text: &str) {
        if let Some(Dialog::Input { editor, .. }) = &mut self.dialog {
            editor.paste(text);
        } else if let Some(editor) = self.form.as_mut().and_then(|form| form.editor.as_mut()) {
            editor.paste(text);
        }
    }
}

fn move_focus(code: KeyCode, selected: &mut usize, count: usize) -> bool {
    match code {
        KeyCode::Up | KeyCode::Left | KeyCode::BackTab => {
            *selected = (*selected + count - 1) % count
        }
        KeyCode::Down | KeyCode::Right | KeyCode::Tab => *selected = (*selected + 1) % count,
        KeyCode::Home => *selected = 0,
        KeyCode::End => *selected = count - 1,
        _ => return false,
    }
    true
}

fn safe_text(text: &str) -> String {
    text.chars()
        .filter(|&c| c == '\n' || !c.is_control())
        .collect()
}

struct Restore {
    focus_reporting: bool,
}

impl Drop for Restore {
    fn drop(&mut self) {
        if self.focus_reporting {
            let _ = execute!(stdout(), DisableFocusChange);
        }
        let _ = execute!(stdout(), DisableBracketedPaste);
        let _ = ratatui::try_restore();
    }
}

pub fn run(launch: Launch, runtime: &Runtime, cancel: CancellationToken) -> Result<()> {
    let mut console = Console::new(launch, runtime);
    let initial_theme = theme::Theme::detect();
    let mut theme = initial_theme.unwrap_or(&theme::Theme::NATIVE);
    let mut refresh_theme = false;
    let mut restore = Restore {
        focus_reporting: false,
    };
    let mut terminal = ratatui::try_init()?;
    execute!(stdout(), EnableBracketedPaste)?;
    if initial_theme.is_some() {
        restore.focus_reporting = execute!(stdout(), EnableFocusChange).is_ok();
    }
    while !(cancel.is_cancelled() || console.quitting && console.service.is_none()) {
        if let Err(error) = console.tick() {
            console.error(error)
        }
        terminal.draw(|frame| theme.draw(&console, frame))?;
        if event::poll(Duration::from_millis(150))? {
            match event::read()? {
                Event::Key(key) => {
                    if let Err(error) = console.key(key) {
                        console.error(error)
                    }
                }
                Event::Paste(text) => console.paste(&text),
                Event::FocusGained => refresh_theme = restore.focus_reporting,
                Event::FocusLost => refresh_theme = false,
                _ => {}
            }
        } else if refresh_theme
            && console.dialog.is_none()
            && console
                .form
                .as_ref()
                .is_none_or(|form| form.editor.is_none())
        {
            // The color query reads the terminal. Wait until keyboard input is idle.
            theme = theme::Theme::detect().unwrap_or(theme);
            refresh_theme = false;
        }
    }
    terminal.clear()?;
    Ok(())
}
