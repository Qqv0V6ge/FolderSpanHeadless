use super::TextEdit;
use anyhow::{Context, Result, ensure};
use folderspan_headless::{
    config::{Launch, Settings},
    instance_lock::LockedProfile,
};
use std::path::PathBuf;

#[derive(Clone, Copy)]
pub(super) enum Field {
    Address,
    Port,
    WebRoot,
    Origins,
}

impl Field {
    pub(super) const ALL: [Self; 4] = [Self::Address, Self::Port, Self::WebRoot, Self::Origins];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Address => "监听地址",
            Self::Port => "监听端口",
            Self::WebRoot => "Web 资源目录",
            Self::Origins => "允许的 Origin",
        }
    }

    pub(super) fn help(self) -> &'static str {
        match self {
            Self::Address => "留空监听所有接口。127.0.0.1 只允许本机连接。",
            Self::Port => "输入 0 至 65535。0 表示启动时自动分配。",
            Self::WebRoot => "填写包含 index.html 的目录。",
            Self::Origins => "以逗号分隔完整来源。* 表示任意来源，留空仅允许同源。",
        }
    }

    pub(super) fn input(self, settings: &Settings) -> String {
        match self {
            Self::Address => settings
                .bind_address
                .map_or_else(String::new, |ip| ip.to_string()),
            Self::Port => settings.port.to_string(),
            Self::WebRoot => settings.web_root.display().to_string(),
            Self::Origins => settings.allowed_origins.clone(),
        }
    }

    pub(super) fn display(self, settings: &Settings) -> String {
        match self {
            Self::Address if settings.bind_address.is_none() => "所有接口".into(),
            Self::Port if settings.port == 0 => "自动分配".into(),
            Self::Origins if settings.allowed_origins.trim().is_empty() => "仅同源".into(),
            Self::Origins if settings.allowed_origins.trim() == "*" => "任意来源 (*)".into(),
            _ => self.input(settings),
        }
    }

    fn same(self, left: &Settings, right: &Settings) -> bool {
        match self {
            Self::Address => left.bind_address == right.bind_address,
            Self::Port => left.port == right.port,
            Self::WebRoot => left.web_root == right.web_root,
            Self::Origins => left.allowed_origins == right.allowed_origins,
        }
    }

    fn apply(self, settings: &mut Settings, value: &str) -> Result<()> {
        match self {
            Self::Address => {
                settings.bind_address = if value.trim().is_empty() {
                    None
                } else {
                    Some(
                        value
                            .trim()
                            .parse()
                            .context("请输入有效的 IPv4 或 IPv6 地址")?,
                    )
                };
            }
            Self::Port => {
                settings.port = value.trim().parse().context("端口应在 0 至 65535 之间")?
            }
            Self::WebRoot => {
                ensure!(!value.is_empty(), "请输入 Web 资源目录");
                settings.web_root = std::path::absolute(PathBuf::from(value))?;
            }
            Self::Origins => {
                let mut candidate = settings.clone();
                candidate.allowed_origins = value.trim().to_owned();
                candidate
                    .policy([])
                    .context("请填写完整的 HTTP 或 HTTPS 来源")?;
                settings.allowed_origins = candidate.allowed_origins;
            }
        }
        Ok(())
    }

    fn copy(self, from: &Settings, to: &mut Settings) {
        match self {
            Self::Address => to.bind_address = from.bind_address,
            Self::Port => to.port = from.port,
            Self::WebRoot => to.web_root = from.web_root.clone(),
            Self::Origins => to.allowed_origins = from.allowed_origins.clone(),
        }
    }
}

pub(super) struct Form {
    original: Settings,
    pub(super) draft: Settings,
    pub(super) saved: bool,
    pub(super) selected: usize,
    pub(super) editor: Option<TextEdit>,
}

impl Form {
    pub(super) const SAVE: usize = Field::ALL.len() + 1;
    pub(super) const ROWS: usize = Self::SAVE + 1;

    pub(super) fn load(launch: &Launch) -> Result<Self> {
        let (original, saved) = launch.load_settings()?;
        Ok(Self {
            draft: original.clone(),
            original,
            saved,
            selected: 1,
            editor: None,
        })
    }

    pub(super) fn field(&self) -> Option<Field> {
        self.selected
            .checked_sub(1)
            .and_then(|index| Field::ALL.get(index).copied())
    }

    pub(super) fn dirty(&self) -> bool {
        Field::ALL.into_iter().any(|field| self.changed(field))
    }

    pub(super) fn changed(&self, field: Field) -> bool {
        !field.same(&self.original, &self.draft)
    }

    pub(super) fn move_by(&mut self, delta: isize) {
        self.selected = (self.selected as isize + delta).rem_euclid(Self::ROWS as isize) as usize;
    }

    pub(super) fn begin(&mut self, field: Field) {
        self.editor = Some(TextEdit::new(field.input(&self.draft)));
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        let field = self.field().expect("an editor belongs to a settings field");
        let editor = self.editor.as_ref().expect("field editor is open");
        field.apply(&mut self.draft, &editor.value)?;
        self.editor = None;
        Ok(())
    }

    pub(super) fn save(&mut self, launch: &Launch) -> Result<()> {
        let profile = LockedProfile::acquire(&launch.data_dir)?;
        let (fresh, _) = launch.load_settings()?;
        let merged = self.merge(fresh)?;
        merged.save(&profile.data_dir)?;
        self.original = merged.clone();
        self.draft = merged;
        self.saved = true;
        Ok(())
    }

    fn merge(&self, mut fresh: Settings) -> Result<Settings> {
        for field in Field::ALL {
            if self.changed(field) {
                ensure!(
                    field.same(&self.original, &fresh) || field.same(&self.draft, &fresh),
                    "{}已在其他窗口更改。请返回主菜单后重新打开部署配置。",
                    field.label(),
                );
                field.copy(&self.draft, &mut fresh);
            }
        }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drafts_validate_fields_and_preserve_other_writers() {
        let temp = tempfile::tempdir().unwrap();
        let launch = Launch::parse(["--data-dir".into(), temp.path().display().to_string()])
            .unwrap()
            .unwrap();
        let mut form = Form::load(&launch).unwrap();
        assert!(!form.dirty());
        form.selected = 2;
        form.begin(Field::Port);
        form.editor.as_mut().unwrap().value = "65536".into();
        assert!(form.finish().is_err());
        assert_eq!(form.draft.port, 12043);
        form.editor.as_mut().unwrap().value = "7000".into();
        form.finish().unwrap();
        assert!(form.dirty());

        let mut fresh = form.original.clone();
        fresh.allowed_origins = String::new();
        let merged = form.merge(fresh.clone()).unwrap();
        assert_eq!(merged.port, 7000);
        assert!(merged.allowed_origins.is_empty());
        fresh.port = 8000;
        assert!(form.merge(fresh).is_err());
        assert!(!temp.path().join("settings.json").exists());
    }
}
