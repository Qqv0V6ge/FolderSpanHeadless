use super::{
    CONFIRM_OPTIONS, Console, Dialog, MENU, Page, TextEdit,
    diagnostics::ResultLevel,
    grant::{DIRECTORY_OPTIONS, GrantFocus, GrantStep, directory_change},
    pages::{Action, Row, Screen},
    safe_text,
    settings::{Field, Form},
    theme::Theme,
};
use folderspan_headless::config::DISPLAY_NAME;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin, Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Clear, Paragraph, Wrap},
};

const TEXT: Style = Style::new();

fn usable(area: Rect) -> bool {
    area.width > 0 && area.height > 0
}

fn inset(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    area.inner(Margin {
        horizontal: horizontal.min(area.width.saturating_sub(1) / 2),
        vertical: vertical.min(area.height.saturating_sub(1) / 2),
    })
}

fn one_line(text: &str) -> String {
    safe_text(text).replace('\n', " ")
}

fn fit(value: &str, width: u16, keep_tail: bool) -> String {
    let width = usize::from(width);
    if width == 0 {
        return String::new();
    }
    if Span::raw(value).width() <= width {
        return value.to_owned();
    }
    let remaining = width - 1;
    let head_budget = if keep_tail { remaining / 2 } else { remaining };
    let mut head_end = 0;
    let mut used = 0;
    for (index, character) in value.char_indices() {
        let end = index + character.len_utf8();
        used += Span::raw(&value[index..end]).width();
        if used > head_budget {
            break;
        }
        head_end = end;
    }
    let mut tail_start = value.len();
    let mut used = 0;
    for (index, character) in value.char_indices().rev() {
        used += Span::raw(&value[index..index + character.len_utf8()]).width();
        if used > remaining - head_budget {
            break;
        }
        tail_start = index;
    }
    format!("{}…{}", &value[..head_end], &value[tail_start..])
}

fn text(frame: &mut Frame, area: Rect, value: impl Into<String>, style: Style) {
    frame.render_widget(
        Paragraph::new(Text::styled(safe_text(&value.into()), style)).wrap(Wrap { trim: true }),
        area,
    );
}

fn source_label(source: &str) -> &str {
    match source {
        "argument" => "启动参数",
        "environment" => "环境变量",
        "saved" => "已保存",
        _ => "默认值",
    }
}

fn columns(area: Rect) -> [Rect; 3] {
    Layout::horizontal([
        Constraint::Length(if area.width >= 34 {
            16
        } else {
            (area.width / 2).min(13)
        }),
        Constraint::Min(0),
        Constraint::Length(if area.width >= 47 { 10 } else { 0 }),
    ])
    .areas(area)
}

fn line(area: Rect, index: u16) -> Rect {
    Rect::new(
        area.x,
        area.y.saturating_add(index),
        area.width,
        u16::from(index < area.height),
    )
}

impl Theme {
    fn title(&self, frame: &mut Frame, area: Rect, value: &str) {
        frame.render_widget(Paragraph::new(value).style(self.accent), area);
    }

    fn header(&self, frame: &mut Frame, area: Rect, console: &Console<'_>) {
        let area = inset(area, 2, 0);
        let first = line(area, 0);
        let key_name = match console.page {
            Page::Grant => console.draft.as_ref().map(|draft| {
                if draft.name.is_empty() {
                    "新增密钥"
                } else {
                    &draft.name
                }
            }),
            Page::KeyActions => console
                .keys()
                .get(console.selected)
                .map(|key| key.name.as_str()),
            _ => None,
        };
        let result = key_name.map(|name| (name, TEXT)).or_else(|| {
            console
                .service
                .as_ref()
                .map(|_| (console.service_state_summary(), self.accent))
        });
        if let Some((value, style)) = result
            && area.width >= 44
        {
            let brand_width = Span::raw(DISPLAY_NAME).width() as u16 + 2;
            let [brand, context] =
                Layout::horizontal([Constraint::Length(brand_width), Constraint::Min(0)])
                    .areas(first);
            self.title(frame, brand, DISPLAY_NAME);
            frame.render_widget(
                Paragraph::new(fit(&one_line(value), context.width, false))
                    .style(style)
                    .alignment(Alignment::Right),
                context,
            );
        } else {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(DISPLAY_NAME, self.accent),
                    Span::styled(concat!("  v", env!("CARGO_PKG_VERSION")), self.muted),
                ])),
                first,
            );
        }
        self.rule(frame, line(area, 1));
    }

    pub(super) fn draw(&self, console: &Console<'_>, frame: &mut Frame) {
        let root = frame.area();
        frame.render_widget(Block::default().style(self.surface), root);
        let footer_lines = if console.notice.is_empty() { 2 } else { 4 };
        let [header_area, body, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(footer_lines.min(root.height / 3)),
        ])
        .areas(root);
        self.header(frame, header_area, console);
        let body = inset(body, 2, 0);

        let hint = match console.page {
            Page::Menu => {
                self.menu(frame, body, console);
                "↑↓ 或 Tab  选择     Enter  打开     数字键  直达"
            }
            Page::Settings => self.settings(frame, body, console),
            Page::Grant => self.grant(frame, body, console),
            _ => {
                self.split_screen(frame, body, &console.screen(), console.cursor);
                "↑↓ 或 Tab  选择     Enter  操作     Esc  返回"
            }
        };
        let hint = console
            .dialog
            .as_ref()
            .map_or(hint, |dialog| self.modal(frame, body, dialog));
        let footer = inset(footer, 2, 0);
        if usable(footer) {
            self.rule(frame, line(footer, 0));
            let shortcuts = line(footer, 1);
            if console.quitting {
                text(frame, shortcuts, "正在等待服务关闭…", self.muted);
            } else {
                text(frame, shortcuts, hint, self.muted);
                if !console.notice.is_empty() {
                    let feedback = Rect::new(
                        footer.x,
                        footer.y + 2,
                        footer.width,
                        footer.height.saturating_sub(2),
                    );
                    text(
                        frame,
                        feedback,
                        &console.notice,
                        if console.has_error {
                            self.alert
                        } else {
                            self.accent
                        },
                    );
                }
            }
        }
    }

    fn row_style(&self, selected: bool) -> (Style, &'static str) {
        if selected {
            (self.focus, "› ")
        } else {
            (TEXT, "  ")
        }
    }

    fn rule(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new("─".repeat(area.width as usize)).style(self.rule),
            area,
        );
    }

    fn split_panes(&self, frame: &mut Frame, area: Rect) -> [Rect; 2] {
        if area.width >= 56 {
            let [left, _, divider, _, right] = Layout::horizontal([
                Constraint::Length(area.width.saturating_sub(5) / 2),
                Constraint::Length(2),
                Constraint::Length(1),
                Constraint::Length(2),
                Constraint::Min(0),
            ])
            .areas(area);
            frame.render_widget(
                Paragraph::new(vec![Line::raw("│"); divider.height as usize]).style(self.rule),
                divider,
            );
            [left, right]
        } else {
            let detail_height = (area.height / 2).max(4).min(area.height.saturating_sub(2));
            let [list, divider, detail] = Layout::vertical([
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(detail_height),
            ])
            .areas(area);
            self.rule(frame, divider);
            [list, detail]
        }
    }

    fn split_screen(&self, frame: &mut Frame, area: Rect, screen: &Screen, cursor: usize) {
        let [list, detail] = self.split_panes(frame, inset(area, 0, u16::from(area.height >= 16)));
        let selected = cursor.min(screen.rows.len() - 1);
        self.render_rows(frame, list, screen, selected, true);
        self.render_detail(frame, detail, &screen.rows[selected]);
    }

    fn render_rows(
        &self,
        frame: &mut Frame,
        area: Rect,
        screen: &Screen,
        selected: usize,
        active: bool,
    ) {
        let heading_height = match area.height {
            0 | 1 => 0,
            2..=4 => 1,
            _ => 2,
        };
        let [heading, rows] =
            Layout::vertical([Constraint::Length(heading_height), Constraint::Min(0)]).areas(area);
        if usable(heading) {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(screen.title, self.accent),
                    Span::raw("  "),
                    Span::styled(screen.state.unwrap_or_default(), self.alert),
                ])),
                heading,
            );
        }
        let offset = selected
            .saturating_add(1)
            .saturating_sub(rows.height as usize);
        let value_width = (rows.width / 3).clamp(12, 18);
        for (index, row) in screen
            .rows
            .iter()
            .enumerate()
            .skip(offset)
            .take(rows.height as usize)
        {
            let area = line(rows, (index - offset) as u16);
            let current = index == selected;
            let focused = current && active;
            let (style, _) = self.row_style(focused);
            frame.render_widget(Block::default().style(style), area);
            let (label_area, value_area) = if !row.value.is_empty() && area.width >= 24 {
                let [label, _, value] = Layout::horizontal([
                    Constraint::Min(0),
                    Constraint::Length(1),
                    Constraint::Length(value_width),
                ])
                .areas(area);
                (label, Some(value))
            } else {
                (area, None)
            };
            let marker = if current { "› " } else { "  " };
            let label = fit(
                &one_line(&row.label),
                label_area.width.saturating_sub(2),
                std::path::Path::new(&row.label).is_absolute(),
            );
            frame.render_widget(Paragraph::new(format!("{marker}{label}")), label_area);
            if let Some(area) = value_area {
                let style = if focused {
                    TEXT
                } else {
                    match row.level {
                        Some(ResultLevel::Ready) => self.accent,
                        Some(ResultLevel::Notice | ResultLevel::Error) => self.alert,
                        None => self.muted,
                    }
                };
                let value = fit(
                    &one_line(&row.value),
                    area.width,
                    row.value.contains(std::path::MAIN_SEPARATOR),
                );
                frame.render_widget(Paragraph::new(Line::from(Span::styled(value, style))), area);
            }
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect, row: &Row) {
        let [heading, body] = Layout::vertical([
            Constraint::Length(if area.height >= 6 { 2 } else { 1 }),
            Constraint::Min(0),
        ])
        .areas(area);
        self.title(
            frame,
            heading,
            &fit(
                &one_line(&row.label),
                heading.width,
                std::path::Path::new(&row.label).is_absolute(),
            ),
        );
        let description = row.description();
        let description = if body.height < 4 {
            description.replace("\n\n", "\n")
        } else {
            description
        };
        text(frame, body, description, TEXT);
    }

    fn grant(&self, frame: &mut Frame, area: Rect, console: &Console<'_>) -> &'static str {
        let flow = &console.grant;
        let [steps, separator, content, actions_rule, actions] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let mut breadcrumb = Vec::new();
        for step in GrantStep::ALL {
            if step != GrantStep::Name {
                breadcrumb.push(Span::styled("  ›  ", self.muted));
            }
            let label = Span::raw(step.label());
            breadcrumb.push(if step == flow.step {
                label.style(self.accent.add_modifier(Modifier::UNDERLINED))
            } else {
                label.style(self.muted)
            });
        }
        frame.render_widget(Paragraph::new(Line::from(breadcrumb)), steps);
        self.rule(frame, separator);

        let screen = console.grant_screen();
        let cursor = flow.cursor().min(screen.rows.len() - 1);
        let content = inset(content, 0, u16::from(content.height >= 14));
        let [list, detail] = self.split_panes(frame, content);
        self.render_rows(frame, list, &screen, cursor, flow.focus == GrantFocus::List);
        match screen.rows[cursor].action {
            Action::Directory(index) => self.directory_detail(frame, detail, console, index),
            _ => self.render_detail(frame, detail, &screen.rows[cursor]),
        }

        self.rule(frame, actions_rule);
        let [back, next] =
            Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(actions);
        let (back_label, next_label) = (
            if flow.step == GrantStep::Name {
                "返回"
            } else {
                "上一步"
            },
            match flow.step {
                GrantStep::Review if console.service.is_some() => "完成",
                GrantStep::Review => "保存权限",
                GrantStep::Directories => "前往复核 →",
                _ => "下一步 →",
            },
        );
        self.action_button(
            frame,
            back,
            back_label,
            flow.focus == GrantFocus::Back,
            Alignment::Left,
        );
        self.action_button(
            frame,
            next,
            next_label,
            flow.focus == GrantFocus::Next,
            Alignment::Right,
        );
        "↑↓ 选择   Tab 换区   Enter 确认   Esc 返回"
    }

    fn action_button(
        &self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        active: bool,
        alignment: Alignment,
    ) {
        let (style, marker) = self.row_style(active);
        let label = Span::styled(
            if active {
                format!("{marker}[ {label} ]")
            } else {
                format!("[ {label} ]")
            },
            style,
        );
        frame.render_widget(Paragraph::new(Line::from(label)).alignment(alignment), area);
    }

    fn directory_detail(&self, frame: &mut Frame, area: Rect, console: &Console<'_>, index: usize) {
        let draft = console.draft.as_ref().expect("permissions are open");
        let directory = &draft.directories[index];
        let path = one_line(&directory.path.display().to_string());
        let path_lines = (Span::raw(&path)
            .width()
            .div_ceil(area.width.max(1) as usize) as u16)
            .clamp(1, area.height.saturating_sub(3).max(1));
        let spacious = area.height >= path_lines + 6;
        let [heading, label, options, change] = Layout::vertical([
            Constraint::Length(path_lines),
            Constraint::Length(u16::from(spacious)),
            Constraint::Length(
                area.height
                    .saturating_sub(path_lines + u16::from(spacious))
                    .min(3),
            ),
            Constraint::Min(0),
        ])
        .areas(area);
        frame.render_widget(
            Paragraph::new(path)
                .style(self.accent)
                .wrap(Wrap { trim: false }),
            heading,
        );
        self.title(frame, label, "权限");
        let focused = match console.grant.focus {
            GrantFocus::Directory(index) => Some(index),
            _ => None,
        };
        let offset = focused
            .unwrap_or(usize::from(directory.write))
            .saturating_add(1)
            .saturating_sub(options.height as usize);
        for (index, option) in DIRECTORY_OPTIONS
            .iter()
            .enumerate()
            .skip(offset)
            .take(options.height as usize)
        {
            let current = index == usize::from(directory.write);
            let marker = match index {
                2 => "    ",
                _ if current => "(*) ",
                _ => "( ) ",
            };
            let (style, focus_marker) = self.row_style(focused == Some(index));
            frame.render_widget(
                Paragraph::new(format!("{focus_marker}{marker}{option}")).style(style),
                line(options, (index - offset) as u16),
            );
        }
        let change_text = directory_change(draft, directory);
        if change.height > 1 {
            text(frame, line(change, 1), change_text, self.accent);
        } else {
            text(frame, change, change_text, self.accent);
        }
    }

    fn menu(&self, frame: &mut Frame, area: Rect, console: &Console<'_>) {
        let wide = area.width >= 63;
        let [navigation, details] = if wide {
            let [nav, _, detail] = Layout::horizontal([
                Constraint::Length(24),
                Constraint::Length(4),
                Constraint::Min(1),
            ])
            .areas(area);
            [nav, detail]
        } else if area.height >= 15 {
            Layout::vertical([Constraint::Length(10), Constraint::Min(1)]).areas(area)
        } else {
            [area, Rect::default()]
        };

        let [heading, list] =
            Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).areas(navigation);
        self.title(frame, heading, "主菜单");
        let spacious = list.height >= 12;
        let offset = if spacious {
            0
        } else {
            console
                .menu
                .saturating_add(1)
                .saturating_sub(list.height as usize)
        };
        let mut row = 0;
        for (index, item) in MENU.iter().enumerate().skip(offset) {
            if spacious && matches!(index, 0 | 3) {
                let group = if index == 0 { "  服务" } else { "  维护" };
                if index != 0 {
                    row += 1;
                }
                text(frame, line(list, row), group, self.muted);
                row += 1;
            }
            if spacious && index == MENU.len() - 1 {
                row += 1;
            }
            if row >= list.height {
                break;
            }
            let selected = index == console.menu;
            let (style, marker) = self.row_style(selected);
            let label = Line::from(vec![
                Span::styled(
                    format!(" {marker} {}   ", item.key),
                    if selected { TEXT } else { self.muted },
                ),
                Span::raw(item.label),
            ]);
            frame.render_widget(Paragraph::new(label).style(style), line(list, row));
            row += 1;
        }
        if usable(details) {
            let item = &MENU[console.menu];
            let [name, description, status] = Layout::vertical([
                Constraint::Length(2),
                Constraint::Length(if wide { 4 } else { 2 }),
                Constraint::Min(0),
            ])
            .areas(details);
            self.title(frame, name, item.label);
            text(frame, description, item.help, TEXT);
            if status.height >= 3 {
                let mut parts = vec![Line::from(Span::styled("服务", self.muted))];
                parts.extend(
                    console
                        .service_state()
                        .lines()
                        .map(|status| Line::raw(status.to_owned())),
                );
                parts.extend([
                    Line::default(),
                    Line::from(Span::styled("数据目录", self.muted)),
                    Line::raw(one_line(&console.launch.data_dir.display().to_string())),
                ]);
                frame.render_widget(Paragraph::new(parts).wrap(Wrap { trim: false }), status);
            }
        }
    }

    fn settings(&self, frame: &mut Frame, area: Rect, console: &Console<'_>) -> &'static str {
        let form = console.form.as_ref().expect("deployment settings are open");
        let effective = console.launch.resolve(form.draft.clone()).settings;
        let sources = console.launch.sources(form.saved);
        let [heading, rest] = Layout::vertical([
            Constraint::Length(if area.height >= 14 { 3 } else { 1 }),
            Constraint::Min(0),
        ])
        .areas(area);
        let state = if console.service.is_some() {
            Span::styled("服务运行中 · 只读", self.alert)
        } else if form.dirty() {
            Span::styled("有未保存的修改", self.alert)
        } else {
            Span::raw("")
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("部署配置", self.accent),
                Span::raw("   "),
                state,
            ])),
            heading,
        );
        if heading.height == 3 {
            let [field, value, source] = columns(line(heading, 2));
            text(frame, field, "  配置项", self.muted);
            text(frame, value, "配置值", self.muted);
            if source.width >= 6 {
                text(frame, source, "来源", self.muted);
            }
        }

        let two_lines = rest.height >= 15;
        let step = if two_lines { 2 } else { 1 };
        let help_size = if rest.height >= 5 { 3 } else { 0 };
        let [fields, help] = Layout::vertical([
            Constraint::Length(
                rest.height
                    .saturating_sub(help_size)
                    .min(step * Form::ROWS as u16),
            ),
            Constraint::Min(0),
        ])
        .areas(rest);
        let visible = (fields.height / step) as usize;
        let offset = form.selected.saturating_add(1).saturating_sub(visible);
        for index in (offset..Form::ROWS).take(visible) {
            let area = line(fields, (index - offset) as u16 * step);
            self.render_field(frame, area, console, &effective, &sources, index);
        }

        if usable(help) {
            let note = match (form.selected, form.field()) {
                (0, _) => "同一数据目录共用一套配置。切换目录会加载该目录的配置。".into(),
                (Form::SAVE, _) => "保存到当前数据目录，服务下次启动时读取。".into(),
                (_, Some(field)) => {
                    let source = sources[form.selected - 1];
                    if matches!(source, "argument" | "environment") {
                        format!(
                            "{} {}优先。将保存的值：{}",
                            field.help(),
                            source_label(source),
                            field.display(&form.draft)
                        )
                    } else {
                        field.help().into()
                    }
                }
                _ => String::new(),
            };
            text(
                frame,
                inset(help, 0, u16::from(help.height >= 3)),
                note,
                self.muted,
            );
        }
        if form.editor.is_some() {
            "Enter 确定字段   Tab 下一项   Ctrl+A 全选   Ctrl+S 保存   Esc 取消编辑"
        } else if console.service.is_some() {
            "↑↓ 或 Tab  选择     停止服务后可编辑     Esc  主菜单"
        } else if form.selected == Form::SAVE {
            "↑↓ 或 Tab  选择     Enter  保存配置     Esc  主菜单"
        } else if form.selected == 0 {
            "↑↓ 或 Tab  选择     Enter  切换目录     Ctrl+S  保存     Esc  主菜单"
        } else {
            "↑↓ 或 Tab  选择     Enter  编辑     Ctrl+S  保存     Esc  主菜单"
        }
    }

    fn render_field(
        &self,
        frame: &mut Frame,
        area: Rect,
        console: &Console<'_>,
        effective: &folderspan_headless::config::Settings,
        sources: &[&str; 4],
        index: usize,
    ) {
        if !usable(area) {
            return;
        }
        let form = console.form.as_ref().expect("deployment settings are open");
        let selected = index == form.selected;
        let editor = form.editor.as_ref().filter(|_| selected);
        let (style, _) = self.row_style(selected && editor.is_none());
        frame.render_widget(Block::default().style(style), area);
        let [label, value, source_area] = columns(area);
        let marker = if selected { "› " } else { "  " };
        if index == Form::SAVE {
            frame.render_widget(
                Paragraph::new(format!("{marker}保存配置"))
                    .style(TEXT.add_modifier(Modifier::BOLD)),
                area,
            );
            return;
        }
        if index == 0 {
            frame.render_widget(Paragraph::new(format!("{marker}数据目录")), label);
            let value = Rect {
                width: area.right().saturating_sub(value.x),
                ..value
            };
            frame.render_widget(
                Paragraph::new(fit(
                    &one_line(&console.launch.data_dir.display().to_string()),
                    value.width,
                    true,
                )),
                value,
            );
            return;
        }
        let field = Field::ALL[index - 1];
        let source = sources[index - 1];
        frame.render_widget(Paragraph::new(format!("{marker}{}", field.label())), label);
        let overridden = matches!(source, "argument" | "environment");
        let value_for_display = if overridden { effective } else { &form.draft };
        let value = Rect {
            width: value
                .width
                .saturating_sub(u16::from(source_area.width > 0) * 2),
            ..value
        };
        if let Some(editor) = editor {
            self.draw_editor(frame, value, editor, console.dialog.is_none());
        } else {
            let display = one_line(&field.display(value_for_display));
            let fitted = fit(&display, value.width, matches!(field, Field::WebRoot));
            frame.render_widget(Paragraph::new(fitted), value);
        }
        if source_area.width >= 6 {
            let source_label = if form.changed(field) && !overridden {
                "待保存"
            } else {
                source_label(source)
            };
            frame.render_widget(
                Paragraph::new(source_label).style(if selected { TEXT } else { self.muted }),
                source_area,
            );
        }
    }

    fn draw_editor(&self, frame: &mut Frame, area: Rect, editor: &TextEdit, active: bool) {
        if !usable(area) {
            return;
        }
        let width = Span::raw(one_line(&editor.value[..editor.cursor])).width();
        let offset = width.saturating_sub(area.width.saturating_sub(1) as usize) as u16;
        let style = if editor.selected_all {
            self.focus
        } else {
            self.panel.add_modifier(Modifier::UNDERLINED)
        };
        frame.render_widget(
            Paragraph::new(one_line(&editor.value))
                .style(style)
                .scroll((0, offset)),
            area,
        );
        if active {
            frame.set_cursor_position(Position::new(
                area.x
                    + width
                        .saturating_sub(usize::from(offset))
                        .min(area.width.saturating_sub(1) as usize) as u16,
                area.y,
            ));
        }
    }

    fn choices(&self, frame: &mut Frame, area: Rect, options: &[&str], selected: usize) {
        let offset = selected
            .saturating_add(1)
            .saturating_sub(area.height as usize);
        for (index, option) in options
            .iter()
            .enumerate()
            .skip(offset)
            .take(area.height as usize)
        {
            let (style, marker) = self.row_style(index == selected);
            frame.render_widget(
                Paragraph::new(format!("{marker}{option}")).style(style),
                line(area, (index - offset) as u16),
            );
        }
    }

    fn modal(&self, frame: &mut Frame, body: Rect, dialog: &Dialog) -> &'static str {
        if !usable(body) {
            return "";
        }
        let width = body.width.min(68);
        let (title, height) = match dialog {
            Dialog::Input { title, .. } => ((*title).into(), 7),
            Dialog::Confirm { .. } => ("确认操作".into(), 9),
            Dialog::Secret(_) => ("新 Web 访问密钥".into(), 10),
            Dialog::Details { title, .. } => (one_line(title), 14),
        };
        let height = body.height.min(height);
        let area = Rect::new(
            body.x + (body.width - width) / 2,
            body.y + (body.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, area);
        let block = Block::bordered()
            .style(self.panel)
            .border_style(self.rule)
            .title_style(self.accent)
            .title(format!(" {title} "));
        let inner = inset(block.inner(area), 2, 1);
        frame.render_widget(block, area);
        match dialog {
            Dialog::Input { editor, .. } => {
                self.draw_editor(frame, line(inner, 0), editor, true);
                "Enter  确认     Esc  取消     Ctrl+A  全选"
            }
            Dialog::Confirm {
                title, selected, ..
            } => {
                let [message, options] = Layout::vertical([
                    Constraint::Length(if inner.height > 3 { 2 } else { 1 }),
                    Constraint::Min(0),
                ])
                .areas(inner);
                text(frame, message, title, TEXT);
                self.choices(frame, options, &CONFIRM_OPTIONS, *selected);
                "↑↓ 或 Tab  选择     Enter  执行     Esc  取消"
            }
            Dialog::Secret(secret) => {
                text(
                    frame,
                    inner,
                    format!("请保存此密钥，本次关闭后无法找回。\n\n{}", secret.as_str()),
                    TEXT,
                );
                "Enter 或 Esc  关闭"
            }
            Dialog::Details {
                text: detail,
                scroll,
                ..
            } => {
                let detail = safe_text(detail);
                let width = usize::from(inner.width.max(1));
                let approximate_lines: usize = detail
                    .lines()
                    .map(|line| Span::raw(line).width().max(1).div_ceil(width))
                    .sum();
                let scroll = usize::from(*scroll)
                    .min(approximate_lines.saturating_sub(inner.height as usize));
                frame.render_widget(
                    Paragraph::new(detail)
                        .wrap(Wrap { trim: false })
                        .scroll((scroll as u16, 0)),
                    inner,
                );
                "↑↓  滚动     Enter 或 Esc  返回"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_paths_keep_the_final_directory_and_fit_the_column() {
        let value = fit("/home/webb/工作区/FolderSpan/资源", 20, true);
        assert!(value.ends_with("/资源"));
        assert!(value.contains('…'));
        assert!(Span::raw(value).width() <= 20);
        assert_eq!(fit("本机", 1, true), "…");
    }
}
