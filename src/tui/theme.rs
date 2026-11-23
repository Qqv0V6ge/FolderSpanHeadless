use ratatui::style::{Color, Modifier, Style};
use std::time::Duration;
use terminal_colorsaurus::{QueryOptions, ThemeMode};

pub(super) struct Theme {
    pub(super) surface: Style,
    pub(super) panel: Style,
    pub(super) muted: Style,
    pub(super) rule: Style,
    pub(super) accent: Style,
    pub(super) alert: Style,
    pub(super) focus: Style,
}

struct Scheme {
    surface: u32,
    surface_container_high: u32,
    on_surface: u32,
    on_surface_variant: u32,
    outline_variant: u32,
    primary: u32,
    on_primary: u32,
    error: u32,
}

impl Theme {
    // FolderSpanPublic core/src/commonMain/kotlin/com/folderspan/ui/theme/Color.kt
    // (cfa07ae). Keep these Material color roles in sync with the client.
    pub(super) const LIGHT: Self = Self::from_scheme(Scheme {
        surface: 0xF7FBEA,
        surface_container_high: 0xE6EADA,
        on_surface: 0x191D13,
        on_surface_variant: 0x424937,
        outline_variant: 0xC2CAB2,
        primary: 0x3E6700,
        on_primary: 0xFFFFFF,
        error: 0xBA1A1A,
    });
    pub(super) const DARK: Self = Self::from_scheme(Scheme {
        surface: 0x11150B,
        surface_container_high: 0x272B21,
        on_surface: 0xE0E4D4,
        on_surface_variant: 0xC2CAB2,
        outline_variant: 0x424937,
        primary: 0x97D945,
        on_primary: 0x1F3700,
        error: 0xFFB4AB,
    });
    pub(super) const NATIVE: Self = Self {
        surface: Style::new().fg(Color::Reset).bg(Color::Reset),
        panel: Style::new().fg(Color::Reset).bg(Color::Reset),
        muted: Style::new().add_modifier(Modifier::DIM),
        rule: Style::new().fg(Color::DarkGray),
        accent: Style::new().add_modifier(Modifier::BOLD),
        alert: Style::new()
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::UNDERLINED),
        focus: Style::new().add_modifier(Modifier::REVERSED),
    };

    const fn from_scheme(scheme: Scheme) -> Self {
        let text = Style::new().fg(rgb(scheme.on_surface));
        Self {
            surface: text.bg(rgb(scheme.surface)),
            panel: text.bg(rgb(scheme.surface_container_high)),
            muted: Style::new().fg(rgb(scheme.on_surface_variant)),
            rule: Style::new().fg(rgb(scheme.outline_variant)),
            accent: Style::new()
                .fg(rgb(scheme.primary))
                .add_modifier(Modifier::BOLD),
            alert: Style::new()
                .fg(rgb(scheme.error))
                .add_modifier(Modifier::BOLD),
            focus: Style::new()
                .fg(rgb(scheme.on_primary))
                .bg(rgb(scheme.primary)),
        }
    }

    pub(super) fn detect() -> Option<&'static Self> {
        if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
            return None;
        }
        let mut options = QueryOptions::default();
        options.timeout = Duration::from_millis(250);
        match terminal_colorsaurus::theme_mode(options).ok()? {
            ThemeMode::Light => Some(&Self::LIGHT),
            ThemeMode::Dark => Some(&Self::DARK),
        }
    }
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}
