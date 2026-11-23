use super::{
    Console, Page,
    diagnostics::{Check, ResultLevel},
    settings::Field,
};
use folderspan_headless::access::{Access, Feature, Key};

#[derive(Clone, Copy)]
pub(super) enum Action {
    Inspect,
    Start,
    Stop,
    Restart,
    RefreshStatus,
    RefreshDiagnostics,
    Export,
    MainMenu,
    Keys,
    Key(usize),
    NewKey,
    EditKey,
    ResetKey,
    RevokeKey,
    EditName,
    ToggleMode,
    ToggleFeature(Feature),
    Directory(usize),
    AddDirectory,
}

pub(super) struct Row {
    pub(super) label: String,
    pub(super) value: String,
    pub(super) detail: String,
    pub(super) action: Action,
    pub(super) level: Option<ResultLevel>,
}

impl Row {
    pub(super) fn action(label: &str, detail: &str, action: Action) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            detail: detail.into(),
            action,
            level: None,
        }
    }

    pub(super) fn value(
        label: &str,
        value: impl Into<String>,
        detail: &str,
        action: Action,
    ) -> Self {
        Self {
            value: value.into(),
            ..Self::action(label, detail, action)
        }
    }

    pub(super) fn inspect(label: &str, value: impl Into<String>, detail: &str) -> Self {
        Self::value(label, value, detail, Action::Inspect)
    }

    fn check(check: &Check) -> Self {
        Self {
            level: Some(check.level),
            ..Self::inspect(check.label, check.summary, &check.detail)
        }
    }

    pub(super) fn description(&self) -> String {
        if self.value.is_empty() || self.value == self.detail {
            self.detail.clone()
        } else if self.detail.is_empty() {
            self.value.clone()
        } else {
            format!("{}\n\n{}", self.value, self.detail)
        }
    }
}

pub(super) struct Screen {
    pub(super) title: &'static str,
    pub(super) rows: Vec<Row>,
    pub(super) state: Option<&'static str>,
}

impl Screen {
    pub(super) fn new(title: &'static str, rows: Vec<Row>) -> Self {
        Self {
            title,
            rows,
            state: None,
        }
    }
}

fn main_menu() -> Row {
    Row::action("返回主菜单", "", Action::MainMenu)
}

fn back_to_keys() -> Row {
    Row::action("返回密钥列表", "", Action::Keys)
}

fn mode(access: &Access) -> &'static str {
    match access {
        Access::Full => "完全访问",
        Access::Scoped { .. } => "自定义授权",
    }
}

fn key_summary(key: &Key) -> String {
    match &key.access {
        Access::Full => "已允许所有功能和文件访问。".into(),
        Access::Scoped {
            features,
            directories,
        } => {
            let features = features
                .iter()
                .copied()
                .map(feature_name)
                .collect::<Vec<_>>();
            let features = if features.is_empty() {
                "无".into()
            } else {
                features.join("、")
            };
            let write = directories.iter().filter(|grant| grant.write).count();
            format!(
                "已授权功能：{features}\n\n目录：{} 个只读，{write} 个读写",
                directories.len() - write
            )
        }
    }
}

pub(super) fn feature_name(feature: Feature) -> &'static str {
    match feature {
        Feature::Storage => "网盘",
        Feature::Devices => "设备",
        Feature::Shares => "文件分享",
        Feature::Mcp => "MCP",
        Feature::OutboundHttp => "出站 HTTP",
    }
}

impl Console<'_> {
    pub(super) fn keys(&self) -> &[Key] {
        self.keys.as_ref().map_or(&[], super::Credentials::keys)
    }

    pub(super) fn screen(&self) -> Screen {
        match self.page {
            Page::Menu | Page::Settings | Page::Grant => unreachable!("rendered separately"),
            Page::Service => self.service_screen(),
            Page::Status => self.status_screen(),
            Page::Diagnostics => self.diagnostics_screen(),
            Page::Keys => self.keys_screen(),
            Page::KeyActions => self.key_actions_screen(),
        }
    }

    fn service_screen(&self) -> Screen {
        let mut rows = vec![Row::inspect(
            "运行状态",
            self.service_state_summary(),
            &self.service_state(),
        )];
        match &self.service {
            Some(service) if !service.cancel.is_cancelled() => {
                rows.push(Row::action(
                    "停止服务",
                    "结束由本窗口启动的服务。",
                    Action::Stop,
                ));
                rows.push(Row::action(
                    "重启服务",
                    "停止服务后，使用当前配置重新启动。",
                    Action::Restart,
                ));
            }
            None => rows.push(Row::action(
                "启动服务",
                "按当前数据目录中的配置启动宿主。",
                Action::Start,
            )),
            Some(_) => {}
        }
        rows.push(main_menu());
        Screen::new("服务启停", rows)
    }

    fn status_screen(&self) -> Screen {
        let mut rows = vec![
            Row::inspect(
                "运行状态",
                self.service_state_summary(),
                &self.service_state(),
            ),
            Row::inspect(
                "数据目录",
                self.launch.data_dir.display().to_string(),
                "当前管理的数据目录。",
            ),
        ];
        if let Some(address) = self.service.as_ref().and_then(|service| service.address) {
            rows.push(Row::inspect(
                "实际监听",
                address.to_string(),
                "由本窗口启动的实例正在使用此地址。",
            ));
        }
        if let Some(status) = &self.status {
            rows.push(Row::check(status));
        }
        if let Ok((settings, _)) = self.launch.load_settings() {
            let settings = self.launch.resolve(settings).settings;
            rows.extend(
                Field::ALL.into_iter().map(|field| {
                    Row::inspect(field.label(), field.display(&settings), field.help())
                }),
            );
        }
        rows.push(Row::action(
            "刷新状态",
            "重新探测本机 Web 管理端点。",
            Action::RefreshStatus,
        ));
        rows.push(main_menu());
        Screen::new("服务状态", rows)
    }

    fn diagnostics_screen(&self) -> Screen {
        let mut rows = self
            .report
            .checks
            .iter()
            .map(Row::check)
            .collect::<Vec<_>>();
        rows.push(Row::action(
            "重新检查",
            "重新检测端口、TLS 证书和 Web 资源。",
            Action::RefreshDiagnostics,
        ));
        rows.push(Row::action(
            "导出摘要",
            "将本次检查保存到一个新文件。",
            Action::Export,
        ));
        rows.push(main_menu());
        Screen::new("运行诊断", rows)
    }

    fn keys_screen(&self) -> Screen {
        let mut rows = vec![Row::action(
            "新增密钥",
            "设置名称和权限后生成一把新密钥。",
            Action::NewKey,
        )];
        for (index, key) in self.keys().iter().enumerate() {
            rows.push(Row::value(
                &key.name,
                mode(&key.access),
                &key_summary(key),
                Action::Key(index),
            ));
        }
        rows.push(main_menu());
        let mut screen = Screen::new("访问控制", rows);
        if self.service.is_some() {
            screen.state = Some("服务运行中 · 只读");
        }
        screen
    }

    fn key_actions_screen(&self) -> Screen {
        let mut rows = Vec::new();
        if let Some(key) = self.keys().get(self.selected) {
            rows.push(Row::inspect("密钥名称", &key.name, &key_summary(key)));
            if self.service.is_some() {
                rows.push(Row::action(
                    "查看权限",
                    "查看功能和目录授权。",
                    Action::EditKey,
                ));
            } else {
                rows.push(Row::action(
                    "编辑名称与权限",
                    "修改完成后统一保存。",
                    Action::EditKey,
                ));
                rows.push(Row::action(
                    "重置密钥",
                    "生成新密钥后，旧密钥失效。",
                    Action::ResetKey,
                ));
                rows.push(Row::action(
                    "撤销密钥",
                    "取消这把密钥的登录权限。",
                    Action::RevokeKey,
                ));
            }
        }
        rows.push(back_to_keys());
        Screen::new("密钥管理", rows)
    }
}
