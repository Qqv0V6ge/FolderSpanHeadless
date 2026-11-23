use super::{
    Console, Draft, move_focus,
    pages::{Action, Row, Screen, feature_name},
};
use anyhow::Result;
use folderspan_headless::access::{DirectoryGrant, Feature};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum GrantStep {
    #[default]
    Name,
    Features,
    Directories,
    Review,
}

impl GrantStep {
    pub(super) const ALL: [Self; 4] = [Self::Name, Self::Features, Self::Directories, Self::Review];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Name => "名称",
            Self::Features => "功能",
            Self::Directories => "目录",
            Self::Review => "复核",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Name => "密钥设置",
            Self::Features => "功能权限",
            Self::Directories => "目录权限",
            Self::Review => "复核权限",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum GrantFocus {
    #[default]
    List,
    Directory(usize),
    Back,
    Next,
}

#[derive(Default)]
pub(super) struct GrantFlow {
    pub(super) step: GrantStep,
    pub(super) focus: GrantFocus,
    cursors: [usize; GrantStep::ALL.len()],
}

impl GrantFlow {
    pub(super) fn cursor(&self) -> usize {
        self.cursors[self.step as usize]
    }

    pub(super) fn select(&mut self, cursor: usize) {
        self.cursors[self.step as usize] = cursor;
    }

    fn open(&mut self, step: GrantStep) {
        self.step = step;
        self.focus = GrantFocus::List;
    }
}

pub(super) const DIRECTORY_OPTIONS: [&str; 3] = ["只读", "读写", "移除目录"];

fn directory_mode(write: bool) -> &'static str {
    DIRECTORY_OPTIONS[usize::from(write)]
}

impl Console<'_> {
    pub(super) fn grant_screen(&self) -> Screen {
        let draft = self.draft.as_ref().expect("permissions are open");
        let editable = self.service.is_none();
        let step = self.grant.step;
        let review = step == GrantStep::Review;
        let mut rows = Vec::new();
        if matches!(step, GrantStep::Name | GrantStep::Review) {
            rows.push(Row::value(
                "密钥名称",
                if draft.name.is_empty() {
                    "尚未填写"
                } else {
                    &draft.name
                },
                if editable && !review {
                    "按 Enter 输入或修改名称。"
                } else {
                    ""
                },
                if editable && !review {
                    Action::EditName
                } else {
                    Action::Inspect
                },
            ));
            rows.push(Row::value(
                "授权方式",
                if draft.full {
                    "完全访问"
                } else {
                    "自定义授权"
                },
                "完全访问允许所有功能和文件访问。自定义授权可逐项设置。",
                if editable && !review {
                    Action::ToggleMode
                } else {
                    Action::Inspect
                },
            ));
        }
        if matches!(step, GrantStep::Features | GrantStep::Review) {
            if draft.full {
                rows.push(Row::inspect(
                    "功能权限",
                    "全部允许",
                    "此密钥拥有完全访问权限。",
                ));
            } else {
                rows.extend(Feature::ALL.into_iter().map(|feature| {
                    let enabled = draft.features.contains(&feature);
                    let (detail, action) = if editable && !review {
                        ("按 Enter 切换授权。", Action::ToggleFeature(feature))
                    } else {
                        ("", Action::Inspect)
                    };
                    Row::value(
                        feature_name(feature),
                        if enabled {
                            "[x] 已允许"
                        } else {
                            "[ ] 未允许"
                        },
                        detail,
                        action,
                    )
                }));
            }
        }
        if matches!(step, GrantStep::Directories | GrantStep::Review) {
            if draft.full {
                rows.push(Row::inspect(
                    "目录权限",
                    "全部读写",
                    "此密钥拥有完全访问权限。",
                ));
            } else {
                rows.extend(
                    draft
                        .directories
                        .iter()
                        .enumerate()
                        .map(|(index, directory)| {
                            let path = directory.path.display().to_string();
                            let change = directory_change(draft, directory);
                            let detail = if change.is_empty() {
                                path.clone()
                            } else {
                                format!("{path}\n\n{change}")
                            };
                            Row::value(
                                &path,
                                directory_mode(directory.write),
                                &detail,
                                if editable && !review {
                                    Action::Directory(index)
                                } else {
                                    Action::Inspect
                                },
                            )
                        }),
                );
                if review {
                    for directory in draft.original.1.directories().unwrap_or_default() {
                        if !draft
                            .directories
                            .iter()
                            .any(|grant| grant.path == directory.path)
                        {
                            let path = directory.path.display().to_string();
                            rows.push(Row::inspect(&path, "待移除", &path));
                        }
                    }
                }
                if draft.directories.is_empty() && (!editable || review) {
                    rows.push(Row::inspect("目录权限", "无", "此密钥没有授权目录。"));
                }
                if editable && !review {
                    rows.push(Row::action(
                        "＋ 添加目录",
                        "输入已存在目录的绝对路径。新目录默认只读。",
                        Action::AddDirectory,
                    ));
                }
            }
        }
        let mut screen = Screen::new(step.title(), rows);
        screen.state = if !editable {
            Some("服务运行中 · 只读")
        } else if draft.dirty() {
            Some("有未保存的修改")
        } else {
            None
        };
        screen
    }

    pub(super) fn grant_key(&mut self, key: KeyEvent) -> Result<()> {
        use GrantFocus::{Back, Directory, List, Next};

        let step = self.grant.step;
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.editable()?;
            self.grant.open(GrantStep::Review);
            self.grant.focus = Next;
            return Ok(());
        }
        let rows = self.grant_screen().rows;
        let cursor = self.grant.cursor().min(rows.len() - 1);
        self.grant.select(cursor);
        let row = &rows[cursor];
        let directory_focus = match row.action {
            Action::Directory(index) => Some(Directory(usize::from(
                self.draft.as_ref().unwrap().directories[index].write,
            ))),
            _ => None,
        };
        match (key.code, self.grant.focus) {
            (KeyCode::Tab, focus) => {
                self.grant.focus = match focus {
                    List => directory_focus.unwrap_or(Back),
                    Directory(_) => Back,
                    Back => Next,
                    Next => List,
                };
            }
            (KeyCode::BackTab, focus) => {
                self.grant.focus = match focus {
                    List => Next,
                    Directory(_) => List,
                    Back => directory_focus.unwrap_or(List),
                    Next => Back,
                };
            }
            (KeyCode::Right, List) => self.grant.focus = directory_focus.unwrap_or(Next),
            (KeyCode::Left, Directory(_) | Back) => self.grant.focus = List,
            (KeyCode::Right, Directory(_) | Back) => self.grant.focus = Next,
            (KeyCode::Left, Next) => self.grant.focus = Back,
            (KeyCode::Esc, Directory(_)) => self.grant.focus = List,
            (KeyCode::Esc, _) => self.request_leave_permissions(),
            (KeyCode::Enter, List) => {
                let row = rows.into_iter().nth(cursor).unwrap();
                if matches!(row.action, Action::Inspect) {
                    self.show_details(row);
                } else {
                    self.run_action(row.action)?;
                }
            }
            (KeyCode::Enter, Directory(option)) => {
                let Action::Directory(index) = row.action else {
                    self.grant.focus = List;
                    return Ok(());
                };
                self.editable()?;
                let directories = &mut self.draft.as_mut().unwrap().directories;
                if option == 2 {
                    directories.remove(index);
                    self.grant.focus = List;
                } else {
                    directories[index].write = option == 1;
                }
            }
            (KeyCode::Enter, Back) if step == GrantStep::Name => self.request_leave_permissions(),
            (KeyCode::Enter, Back) => self.grant.open(GrantStep::ALL[step as usize - 1]),
            (KeyCode::Enter, Next) if step == GrantStep::Review => {
                if self.service.is_some() {
                    self.leave_permissions();
                } else {
                    self.save_draft()?;
                }
            }
            (KeyCode::Enter, Next) => self.grant.open(GrantStep::ALL[step as usize + 1]),
            (code @ (KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End), List) => {
                let mut cursor = cursor;
                move_focus(code, &mut cursor, rows.len());
                self.grant.select(cursor);
            }
            (
                code @ (KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End),
                Directory(mut option),
            ) => {
                move_focus(code, &mut option, DIRECTORY_OPTIONS.len());
                self.grant.focus = Directory(option);
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn directory_change(draft: &Draft, directory: &DirectoryGrant) -> String {
    match draft
        .original
        .1
        .directories()
        .unwrap_or_default()
        .iter()
        .find(|grant| grant.path == directory.path)
    {
        Some(original) if original.write == directory.write => String::new(),
        Some(original) => format!(
            "待保存    {} → {}",
            directory_mode(original.write),
            directory_mode(directory.write)
        ),
        None => format!("待添加    {}", directory_mode(directory.write)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::{Page, theme::Theme};
    use folderspan_headless::{
        access::{Access, Credentials},
        config::Launch,
    };
    use ratatui::{Terminal, backend::TestBackend, style::Color};

    #[test]
    fn keyboard_edits_directory_in_place_and_saves_only_from_review() -> Result<()> {
        let profile = tempfile::tempdir()?;
        let media = profile.path().join("media");
        let backup = profile.path().join("backup");
        std::fs::create_dir(&media)?;
        std::fs::create_dir(&backup)?;
        let mut credentials = Credentials::load(profile.path())?;
        credentials.add(
            "自动备份".into(),
            Access::Scoped {
                features: Default::default(),
                directories: vec![
                    DirectoryGrant {
                        path: media,
                        write: false,
                    },
                    DirectoryGrant {
                        path: backup,
                        write: false,
                    },
                ],
            },
        )?;
        credentials.save(profile.path())?;
        let launch = Launch::parse(["--data-dir".into(), profile.path().display().to_string()])?
            .expect("launch");
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let mut console = Console::new(launch, &runtime);
        let press =
            |console: &mut Console<'_>, code| console.key(KeyEvent::new(code, KeyModifiers::NONE));
        for code in [KeyCode::Char('6'), KeyCode::Enter, KeyCode::Enter] {
            press(&mut console, code)?;
        }
        assert!(console.page == Page::Grant);
        for code in [
            KeyCode::Right,
            KeyCode::Enter,
            KeyCode::Enter,
            KeyCode::Right,
            KeyCode::Enter,
            KeyCode::Down,
        ] {
            press(&mut console, code)?;
        }
        assert_eq!(console.grant.step, GrantStep::Directories);
        assert_eq!(console.grant.cursor(), 1);
        press(&mut console, KeyCode::Tab)?;
        assert_eq!(console.grant.focus, GrantFocus::Directory(0));
        press(&mut console, KeyCode::Down)?;
        assert!(!console.draft.as_ref().unwrap().directories[1].write);
        press(&mut console, KeyCode::Enter)?;
        assert!(console.draft.as_ref().unwrap().directories[1].write);
        assert!(console.dialog.is_none());

        for theme in [&Theme::LIGHT, &Theme::DARK, &Theme::NATIVE] {
            for (width, height) in [(80, 24), (48, 14)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height))?;
                terminal.draw(|frame| theme.draw(&console, frame))?;
                let cells = terminal.backend().buffer().content();
                let background = theme.surface.bg.unwrap();
                assert_eq!(cells[0].bg, background);
                let selected = cells.iter().find(|cell| cell.symbol() == "*").unwrap();
                assert_eq!(selected.bg, theme.focus.bg.unwrap_or(background));
                assert_eq!(selected.fg, theme.focus.fg.unwrap_or(Color::Reset));
                assert!(selected.modifier.contains(theme.focus.add_modifier));
                let header = cells[..usize::from(width)]
                    .iter()
                    .map(|cell| cell.symbol().trim())
                    .collect::<String>();
                assert!(header.ends_with("自动备份") && !header.contains("密钥名称"));
                let screen = cells
                    .iter()
                    .map(|cell| cell.symbol().trim())
                    .collect::<String>();
                assert!(screen.contains("前往复核"));
                assert!(screen.contains("(*)读写"));
                assert_eq!(screen.matches("↑↓选择").count(), 1);
            }
        }

        for code in [KeyCode::Tab, KeyCode::Right, KeyCode::Enter] {
            press(&mut console, code)?;
        }
        assert_eq!(console.grant.step, GrantStep::Review);
        assert!(
            !Credentials::load(profile.path())?.keys()[0]
                .access
                .directories()
                .unwrap()[1]
                .write
        );
        for code in [KeyCode::Tab, KeyCode::Enter] {
            press(&mut console, code)?;
        }
        assert_eq!(console.grant.step, GrantStep::Directories);
        assert_eq!(console.grant.cursor(), 1);
        for code in [
            KeyCode::BackTab,
            KeyCode::Enter,
            KeyCode::BackTab,
            KeyCode::Enter,
        ] {
            press(&mut console, code)?;
        }
        assert!(console.page == Page::Keys);
        let credentials = Credentials::load(profile.path())?;
        let access = &credentials.keys()[0].access;
        assert!(access.allows(Feature::Storage));
        let directories = access.directories().unwrap();
        assert!(!directories[0].write);
        assert!(directories[1].write);
        Ok(())
    }
}
