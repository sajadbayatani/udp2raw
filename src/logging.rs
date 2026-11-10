use crate::config::Config;
use std::{fmt, sync::OnceLock, time::SystemTime};

struct Settings {
    level: u8,
    color: bool,
    position: bool,
}
static SETTINGS: OnceLock<Settings> = OnceLock::new();
pub fn init(c: &Config) {
    let _ = SETTINGS.set(Settings {
        level: c.log_level,
        color: c.log_color,
        position: c.log_position,
    });
}
pub fn enabled(level: u8) -> bool {
    level != 0 && level <= SETTINGS.get().map_or(4, |s| s.level)
}
pub fn emit(level: u8, file: &str, line: u32, module: &str, args: fmt::Arguments<'_>) {
    let names = ["", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
    let colors = [
        "", "\x1b[31m", "\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[35m", "\x1b[36m",
    ];
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let color = SETTINGS.get().is_some_and(|s| s.color);
    let position = SETTINGS.get().is_some_and(|s| s.position);
    let prefix = if color { colors[level as usize] } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let name = names[level as usize];
    let place = if position {
        format!(" [{file}:{line} {module}]")
    } else {
        String::new()
    };
    eprintln!(
        "{prefix}[{}.{:03} {name}]{place} {args}{reset}",
        timestamp.as_secs(),
        timestamp.subsec_millis()
    );
}
#[macro_export]
macro_rules! log {
    ($level:expr,$($arg:tt)+) => {{
        let lvl=$level;
        if $crate::logging::enabled(lvl){
            $crate::logging::emit(lvl,file!(),line!(),module_path!(),format_args!($($arg)+));
        }
    }};
}
