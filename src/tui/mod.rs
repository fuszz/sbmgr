use std::fs;
use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::backend::var_creator::VarCreator;
use crate::backend::var_reader::VarReader;
use crate::backend::var_writer::VarWriter;

const SEGMENTS: [&str; 5] = [
    "System and Secure Boot status",
    "Registered keys and db/dbx",
    "Create keys and save to files",
    "Register keys from files",
    "Bootloader hash and boot entry",
];

const SEGMENT_ACTIONS: [&[&str]; 5] = [
    &["Refresh status", "List Secure Boot variables"],
    &[
        "Show PK (hex preview)",
        "Show KEK (hex preview)",
        "Show db (hex preview)",
        "Show dbx (hex preview)",
        "List BootXXXX entries",
    ],
    &[  
        "Create PK / KEK key pair files",
        "Create PK auth file"
    ],
    &[
        "Register PK from file",
        "Register KEK from file",
        "Register db from file",
        "Register dbx from file",
    ],
    &[
        "Sign bootloader to .sig",
        "Register bootloader hash as boot entry",
    ],
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    Segments,
    Actions,
    Details,
}

#[derive(Clone, Copy)]
enum ActionKey {
    RefreshStatus,
    ListSbVars,
    ShowPk,
    ShowKek,
    ShowDb,
    ShowDbx,
    ListBootEntries,
    CreateKeyPair,
    CreatePkEsl,
    RegisterPkFile,
    RegisterKekFile,
    RegisterDbFile,
    RegisterDbxFile,
    SignBootloader,
    RegisterBootEntry,
}

pub fn run() -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    stdout
        .execute(EnterAlternateScreen)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    let mut app = App::default();

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode().context("failed to disable raw mode")?;
    io::stdout()
        .execute(LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;

    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if app.input_mode {
                handle_input_mode(app, key.code);
                continue;
            }

            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Left => move_focus_left(app),
                KeyCode::Right => move_focus_right(app),
                KeyCode::Tab => move_focus_right(app),
                KeyCode::BackTab => move_focus_left(app),
                KeyCode::Up => move_up(app),
                KeyCode::Down => move_down(app),
                KeyCode::PageUp => scroll_log_up(app, 5),
                KeyCode::PageDown => scroll_log_down(app, 5),
                KeyCode::Home => app.log_scroll = 0,
                KeyCode::End => app.log_scroll = usize::MAX,
                KeyCode::Char('e') => start_field_edit(app),
                KeyCode::Char('r') => run_current_action(app),
                KeyCode::Enter => handle_enter(app),
                _ => {}
            }
        }
    }

    Ok(())
}

fn handle_enter(app: &mut App) {
    match app.focus {
        FocusPane::Segments => app.focus = FocusPane::Actions,
        FocusPane::Actions => app.focus = FocusPane::Details,
        FocusPane::Details => {
            if details_field_count(app.current_action()) > 0 {
                start_field_edit(app);
            } else {
                run_current_action(app);
            }
        }
    }
}

fn start_field_edit(app: &mut App) {
    if details_field_count(app.current_action()) > 0 {
        app.input_mode = true;
    } else {
        app.logs
            .push("This action has no editable fields.".to_string());
    }
    trim_logs(&mut app.logs);
}

fn handle_input_mode(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.input_mode = false;
        }
        KeyCode::Tab => {
            let count = details_field_count(app.current_action());
            if count > 0 {
                app.details_index = (app.details_index + 1) % count;
            }
        }
        KeyCode::BackTab => {
            let count = details_field_count(app.current_action());
            if count > 0 {
                if app.details_index == 0 {
                    app.details_index = count - 1;
                } else {
                    app.details_index -= 1;
                }
            }
        }
        KeyCode::Enter => {
            app.input_mode = false;
        }
        KeyCode::Backspace => {
            let action = app.current_action();
            if let Some(field) = get_field_mut(app, action, app.details_index) {
                field.pop();
            }
        }
        KeyCode::Char(c) => {
            let action = app.current_action();
            if let Some(field) = get_field_mut(app, action, app.details_index) {
                field.push(c);
            }
        }
        _ => {}
    }
    trim_logs(&mut app.logs);
}

fn move_focus_left(app: &mut App) {
    app.focus = match app.focus {
        FocusPane::Segments => FocusPane::Details,
        FocusPane::Actions => FocusPane::Segments,
        FocusPane::Details => FocusPane::Actions,
    }
}

fn move_focus_right(app: &mut App) {
    app.focus = match app.focus {
        FocusPane::Segments => FocusPane::Actions,
        FocusPane::Actions => FocusPane::Details,
        FocusPane::Details => FocusPane::Segments,
    }
}

fn move_up(app: &mut App) {
    match app.focus {
        FocusPane::Segments => {
            if app.selected_segment == 0 {
                app.selected_segment = SEGMENTS.len() - 1;
            } else {
                app.selected_segment -= 1;
            }
            let actions_len = SEGMENT_ACTIONS[app.selected_segment].len();
            if app.selected_action[app.selected_segment] >= actions_len {
                app.selected_action[app.selected_segment] = 0;
            }
            app.details_index = 0;
        }
        FocusPane::Actions => {
            let idx = app.selected_segment;
            if app.selected_action[idx] == 0 {
                app.selected_action[idx] = SEGMENT_ACTIONS[idx].len() - 1;
            } else {
                app.selected_action[idx] -= 1;
            }
            app.details_index = 0;
        }
        FocusPane::Details => {
            let count = details_field_count(app.current_action());
            if count > 0 {
                if app.details_index == 0 {
                    app.details_index = count - 1;
                } else {
                    app.details_index -= 1;
                }
            }
        }
    }
}

fn move_down(app: &mut App) {
    match app.focus {
        FocusPane::Segments => {
            app.selected_segment = (app.selected_segment + 1) % SEGMENTS.len();
            let actions_len = SEGMENT_ACTIONS[app.selected_segment].len();
            if app.selected_action[app.selected_segment] >= actions_len {
                app.selected_action[app.selected_segment] = 0;
            }
            app.details_index = 0;
        }
        FocusPane::Actions => {
            let idx = app.selected_segment;
            app.selected_action[idx] = (app.selected_action[idx] + 1) % SEGMENT_ACTIONS[idx].len();
            app.details_index = 0;
        }
        FocusPane::Details => {
            let count = details_field_count(app.current_action());
            if count > 0 {
                app.details_index = (app.details_index + 1) % count;
            }
        }
    }
}

fn run_current_action(app: &mut App) {
    app.last_action = current_action_title(app).to_string();
    
    // Add separator if there are previous logs
    if !app.logs.is_empty() {
        app.logs.push("=".repeat(50).to_string());
    }
    
    // Add action header
    app.logs.push(format!(">>> {}", app.last_action));
    app.log_scroll = 0;

    match app.current_action() {
        ActionKey::RefreshStatus => app.logs.extend(refresh_status()),
        ActionKey::ListSbVars => app.logs.extend(list_sb_vars()),
        ActionKey::ShowPk => app.logs.extend(preview_key_bytes("PK")),
        ActionKey::ShowKek => app.logs.extend(preview_key_bytes("KEK")),
        ActionKey::ShowDb => app.logs.extend(preview_key_bytes("db")),
        ActionKey::ShowDbx => app.logs.extend(preview_key_bytes("dbx")),
        ActionKey::ListBootEntries => app.logs.extend(list_boot_entries()),
        ActionKey::CreateKeyPair => {
            let creator = VarCreator::new();
            match creator.create_key_pair(&app.create_key_pair_name, &app.create_key_pair_prefix) {
                Ok(()) => app
                    .logs
                    .push(format!("Key pair created: {}.key, {}.crt", app.create_key_pair_prefix, app.create_key_pair_prefix)),
                Err(err) => app.logs.push(format!("PK creation failed: {err}")),
            }
        }
        ActionKey::CreatePkEsl => {
            if app.esl_source_file.is_empty() || app.esl_dest_file.is_empty() {
                app.logs.push("Provide both source and destination file paths.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let creator = VarCreator::new();
            match creator.sign_efi_var_file("PK", &app.esl_source_file, &app.esl_dest_file) {
                Ok(()) => app.logs.push(format!("PK auth created: {}", app.esl_dest_file)),
                Err(err) => app.logs.push(format!("PK auth creation failed: {err}")),
            }
        }
        ActionKey::RegisterPkFile => {
            if app.register_pk_path.is_empty() {
                app.logs
                    .push("Provide a PK file path in the Action window first.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let mut writer = match VarWriter::new() {
                Ok(w) => w,
                Err(err) => {
                    app.logs.push(format!("VarWriter init failed: {err}"));
                    trim_logs(&mut app.logs);
                    return;
                }
            };

            match writer.write_pk_from_file(&app.register_pk_path) {
                Ok(()) => app.logs.push("PK registered in NVRAM.".to_string()),
                Err(err) => app.logs.push(format!("PK registration failed: {err}")),
            }
        }
        ActionKey::RegisterKekFile => {
            if app.register_kek_path.is_empty() {
                app.logs
                    .push("Provide a KEK file path in the Action window first.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let mut writer = match VarWriter::new() {
                Ok(w) => w,
                Err(err) => {
                    app.logs.push(format!("VarWriter init failed: {err}"));
                    trim_logs(&mut app.logs);
                    return;
                }
            };

            match writer.write_kek_from_file(&app.register_kek_path) {
                Ok(()) => app.logs.push("KEK registered in NVRAM.".to_string()),
                Err(err) => app.logs.push(format!("KEK registration failed: {err}")),
            }
        }
        ActionKey::RegisterDbFile => {
            if app.register_db_path.is_empty() {
                app.logs
                    .push("Provide a db file path in the Action window first.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let mut writer = match VarWriter::new() {
                Ok(w) => w,
                Err(err) => {
                    app.logs.push(format!("VarWriter init failed: {err}"));
                    trim_logs(&mut app.logs);
                    return;
                }
            };

            match writer.write_db_from_file(&app.register_db_path) {
                Ok(()) => app.logs.push("db registered in NVRAM.".to_string()),
                Err(err) => app.logs.push(format!("db registration failed: {err}")),
            }
        }
        ActionKey::RegisterDbxFile => {
            if app.register_dbx_path.is_empty() {
                app.logs
                    .push("Provide a dbx file path in the Action window first.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let mut writer = match VarWriter::new() {
                Ok(w) => w,
                Err(err) => {
                    app.logs.push(format!("VarWriter init failed: {err}"));
                    trim_logs(&mut app.logs);
                    return;
                }
            };

            match writer.write_dbx_from_file(&app.register_dbx_path) {
                Ok(()) => app.logs.push("dbx registered in NVRAM.".to_string()),
                Err(err) => app.logs.push(format!("dbx registration failed: {err}")),
            }
        }
        ActionKey::SignBootloader => {
            if app.bootloader_path.is_empty() {
                app.logs
                    .push("Provide a bootloader path in the Action window first.".to_string());
                trim_logs(&mut app.logs);
                return;
            }

            let creator = VarCreator::new();
            match creator.sign_bootloader(&app.bootloader_path) {
                Ok(sig) => {
                    let out_path = format!("{}.sig", app.bootloader_path);
                    match fs::write(&out_path, &sig) {
                        Ok(()) => app.logs.push(format!(
                            "Bootloader signed. Signature saved to {}",
                            out_path
                        )),
                        Err(err) => {
                            app.logs.push(format!("Signature created but save failed: {err}"))
                        }
                    }
                }
                Err(err) => app.logs.push(format!("Bootloader signing failed: {err}")),
            }
        }
        ActionKey::RegisterBootEntry => app.logs.push(format!(
            "[PLACEHOLDER] Boot entry registration is not implemented yet for: {}",
            app.bootloader_path
        )),
    }

    trim_logs(&mut app.logs);
}

fn trim_logs(logs: &mut Vec<String>) {
    if logs.len() > 1024 {
        let to_drop = logs.len() - 1024;
        logs.drain(0..to_drop);
    }
}

fn scroll_log_up(app: &mut App, lines: usize) {
    app.log_scroll = app.log_scroll.saturating_sub(lines);
}

fn scroll_log_down(app: &mut App, lines: usize) {
    app.log_scroll = app.log_scroll.saturating_add(lines);
}

fn current_action_title(app: &App) -> &'static str {
    SEGMENT_ACTIONS[app.selected_segment][app.selected_action[app.selected_segment]]
}

fn refresh_status() -> Vec<String> {
    let mut lines = vec!["Refreshing Secure Boot status...".to_string()];

    let mut reader = match VarReader::default() {
        Ok(r) => r,
        Err(err) => {
            lines.push(format!("VarReader init failed: {err}"));
            return lines;
        }
    };

    if let Err(err) = reader.update_variable_guids() {
        lines.push(format!("Failed to enumerate variables: {err}"));
        return lines;
    }

    lines.push(format!("UEFI variable count: {}", reader.variables.len()));
    match reader.is_secure_boot_active() {
        Ok(v) => lines.push(format!("SecureBoot: {v}")),
        Err(err) => lines.push(format!("SecureBoot error: {err}")),
    }
    match reader.is_setup_mode_active() {
        Ok(v) => lines.push(format!("SetupMode: {v}")),
        Err(err) => lines.push(format!("SetupMode error: {err}")),
    }
    match reader.is_audit_mode_active() {
        Ok(v) => lines.push(format!("AuditMode: {v}")),
        Err(err) => lines.push(format!("AuditMode error: {err}")),
    }
    match reader.is_shim_active() {
        Ok(v) => lines.push(format!("Shim active: {v}")),
        Err(err) => lines.push(format!("Shim status error: {err}")),
    }

    lines
}

fn list_sb_vars() -> Vec<String> {
    let mut lines = vec!["Listing Secure Boot variables...".to_string()];

    let mut reader = match VarReader::default() {
        Ok(r) => r,
        Err(err) => {
            lines.push(format!("VarReader init failed: {err}"));
            return lines;
        }
    };

    if let Err(err) = reader.update_variable_guids() {
        lines.push(format!("Failed to enumerate variables: {err}"));
        return lines;
    }

    let wanted = ["SecureBoot", "SetupMode", "AuditMode", "PK", "KEK", "db", "dbx"];
    for name in wanted {
        if let Some((n, guid)) = reader.variables.iter().find(|(n, _)| n == name) {
            lines.push(format!("{n} [{guid}]"));
        } else {
            lines.push(format!("{name} [missing]"));
        }
    }

    lines
}

fn preview_key_bytes(which: &str) -> Vec<String> {
    let mut lines = vec![format!("Reading {which}...")];

    let mut reader = match VarReader::default() {
        Ok(r) => r,
        Err(err) => {
            lines.push(format!("VarReader init failed: {err}"));
            return lines;
        }
    };

    if let Err(err) = reader.update_variable_guids() {
        lines.push(format!("Failed to enumerate variables: {err}"));
        return lines;
    }

    let data = match which {
        "PK" => reader.get_pk(),
        "KEK" => reader.get_kek(),
        "db" => reader.get_db(),
        "dbx" => reader.get_dbx(),
        _ => unreachable!(),
    };

    match data {
        Ok(bytes) => {
            lines.push(format!("Size: {} bytes", bytes.len()));
            let preview = bytes
                .iter()
                .take(48)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(" ");
            lines.push(format!("Hex[0..48]: {preview}"));
        }
        Err(err) => lines.push(format!("Read failed: {err}")),
    }

    lines
}

fn list_boot_entries() -> Vec<String> {
    let mut lines = vec!["Listing BootXXXX entries...".to_string()];

    let mut reader = match VarReader::default() {
        Ok(r) => r,
        Err(err) => {
            lines.push(format!("VarReader init failed: {err}"));
            return lines;
        }
    };

    if let Err(err) = reader.update_variable_guids() {
        lines.push(format!("Failed to enumerate variables: {err}"));
        return lines;
    }

    match reader.get_boot_entries_list() {
        Ok(entries) => {
            lines.push(format!("Entry count: {}", entries.len()));
            for (name, guid) in entries.iter().take(10) {
                lines.push(format!("{name} [{guid}]"));
            }
            if entries.len() > 10 {
                lines.push("... truncated to first 10 entries".to_string());
            }
        }
        Err(err) => lines.push(format!("Boot entry listing failed: {err}")),
    }

    lines
}

fn pane_block(title: &str, focused: bool) -> Block<'_> {
    if focused {
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::Blue))
    } else {
        Block::default().borders(Borders::ALL).title(title)
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let outer = Block::default().borders(Borders::ALL).title("sbmgr");
    let inner = outer.inner(frame.area());
    frame.render_widget(outer, frame.area());

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(inner);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(28),
            Constraint::Percentage(48),
        ])
        .split(vertical[0]);

    let segments = SEGMENTS
        .iter()
        .enumerate()
        .map(|(idx, title)| {
            let marker = if idx == app.selected_segment { ">" } else { " " };
            ListItem::new(format!("{marker} {title}"))
        })
        .collect::<Vec<ListItem>>();
    frame.render_widget(
        List::new(segments).block(pane_block("1) Action segment", app.focus == FocusPane::Segments)),
        columns[0],
    );

    let action_items = SEGMENT_ACTIONS[app.selected_segment]
        .iter()
        .enumerate()
        .map(|(idx, title)| {
            let marker = if idx == app.selected_action[app.selected_segment] {
                ">"
            } else {
                " "
            };
            ListItem::new(format!("{marker} {title}"))
        })
        .collect::<Vec<ListItem>>();
    frame.render_widget(
        List::new(action_items).block(pane_block("2) Action menu", app.focus == FocusPane::Actions)),
        columns[1],
    );

    let details_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(columns[2]);

    let fields_text = build_fields_text(app);
    frame.render_widget(
        Paragraph::new(fields_text)
            .wrap(Wrap { trim: false })
            .block(pane_block("3) Action window", app.focus == FocusPane::Details)),
        details_split[0],
    );

    let logs_text = build_logs_text(app);
    let total_log_lines = logs_text.lines().count();
    let viewport_lines = details_split[1].height.saturating_sub(2) as usize;
    let max_scroll = total_log_lines.saturating_sub(viewport_lines);
    let effective_scroll = app.log_scroll.min(max_scroll);
    frame.render_widget(
        Paragraph::new(logs_text)
            .scroll((effective_scroll as u16, 0))
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Result log")),
        details_split[1],
    );

    let footer_help = if app.input_mode {
        "-- EDIT --  Enter: save  Esc: cancel  Tab/Shift+Tab: next/prev field"
    } else {
        "Tab/Shift+Tab: pane  Arrows: move  Enter: continue/execute  e: edit  r: run  PgUp/PgDn: scroll log  Home/End: top/bottom  q: quit"
    };
    frame.render_widget(
        Paragraph::new(footer_help)
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true }),
        vertical[1],
    );
}

fn build_fields_text(app: &App) -> String {
    let action = app.current_action();
    let mut lines = Vec::new();

    lines.push(format!("Segment: {}", SEGMENTS[app.selected_segment]));
    lines.push(format!(
        "Action: {}",
        SEGMENT_ACTIONS[app.selected_segment][app.selected_action[app.selected_segment]]
    ));
    lines.push(String::new());

    let field_count = details_field_count(action);
    if field_count == 0 {
        lines.push("No fields required for this action.".to_string());
    } else {
        for idx in 0..field_count {
            let pointer = if idx == app.details_index { ">" } else { " " };
            let edit_state = if app.input_mode && idx == app.details_index {
                " [editing]"
            } else {
                ""
            };
            lines.push(format!(
                "{pointer} {}: {}{}",
                field_label(action, idx),
                get_field(app, action, idx).unwrap_or_default(),
                edit_state
            ));
        }
    }

    lines.join("\n")
}

fn build_logs_text(app: &App) -> String {
    let mut lines = Vec::new();

    if app.logs.is_empty() {
        lines.push("No actions performed yet.".to_string());
    } else {
        lines.extend(app.logs.iter().cloned());
    }

    lines.join("\n")
}

fn details_field_count(action: ActionKey) -> usize {
    match action {
        ActionKey::CreateKeyPair => 2,
        ActionKey::CreatePkEsl => 2,
        ActionKey::RegisterPkFile => 1,
        ActionKey::RegisterKekFile => 1,
        ActionKey::RegisterDbFile => 1,
        ActionKey::RegisterDbxFile => 1,
        ActionKey::SignBootloader => 1,
        ActionKey::RegisterBootEntry => 1,
        _ => 0,
    }
}

fn field_label(action: ActionKey, idx: usize) -> &'static str {
    match action {
        ActionKey::CreateKeyPair => match idx {
            0 => "PK common name",
            _ => "PK file prefix",
        },
        ActionKey::CreatePkEsl => match idx {
            0 => "Source cert file",
            _ => "Destination auth file",
        },
        ActionKey::RegisterPkFile => "PK file path",
        ActionKey::RegisterKekFile => "KEK file path",
        ActionKey::RegisterDbFile => "db file path",
        ActionKey::RegisterDbxFile => "dbx file path",
        ActionKey::SignBootloader => "Bootloader path",
        ActionKey::RegisterBootEntry => "Bootloader path",
        _ => "-",
    }
}

fn get_field<'a>(app: &'a App, action: ActionKey, idx: usize) -> Option<&'a str> {
    match action {
        ActionKey::CreateKeyPair => match idx {
            0 => Some(&app.create_key_pair_name),
            1 => Some(&app.create_key_pair_prefix),
            _ => None,
        },
        ActionKey::CreatePkEsl => match idx {
            0 => Some(&app.esl_source_file),
            1 => Some(&app.esl_dest_file),
            _ => None,
        },
        ActionKey::RegisterPkFile => Some(&app.register_pk_path),
        ActionKey::RegisterKekFile => Some(&app.register_kek_path),
        ActionKey::RegisterDbFile => Some(&app.register_db_path),
        ActionKey::RegisterDbxFile => Some(&app.register_dbx_path),
        ActionKey::SignBootloader => Some(&app.bootloader_path),
        ActionKey::RegisterBootEntry => Some(&app.bootloader_path),
        _ => None,
    }
}

fn get_field_mut<'a>(app: &'a mut App, action: ActionKey, idx: usize) -> Option<&'a mut String> {
    match action {
        ActionKey::CreateKeyPair => match idx {
            0 => Some(&mut app.create_key_pair_name),
            1 => Some(&mut app.create_key_pair_prefix),
            _ => None,
        },
        ActionKey::CreatePkEsl => match idx {
            0 => Some(&mut app.esl_source_file),
            1 => Some(&mut app.esl_dest_file),
            _ => None,
        },
        ActionKey::RegisterPkFile => Some(&mut app.register_pk_path),
        ActionKey::RegisterKekFile => Some(&mut app.register_kek_path),
        ActionKey::RegisterDbFile => Some(&mut app.register_db_path),
        ActionKey::RegisterDbxFile => Some(&mut app.register_dbx_path),
        ActionKey::SignBootloader => Some(&mut app.bootloader_path),
        ActionKey::RegisterBootEntry => Some(&mut app.bootloader_path),
        _ => None,
    }
}

struct App {
    focus: FocusPane,
    selected_segment: usize,
    selected_action: [usize; 5],
    details_index: usize,
    input_mode: bool,
    logs: Vec<String>,
    last_action: String,
    log_scroll: usize,
    create_key_pair_name: String,
    create_key_pair_prefix: String,
    esl_source_file: String,
    esl_dest_file: String,
    register_pk_path: String,
    register_kek_path: String,
    register_db_path: String,
    register_dbx_path: String,
    bootloader_path: String,
}

impl App {
    fn current_action(&self) -> ActionKey {
        match (self.selected_segment, self.selected_action[self.selected_segment]) {
            (0, 0) => ActionKey::RefreshStatus,
            (0, _) => ActionKey::ListSbVars,
            (1, 0) => ActionKey::ShowPk,
            (1, 1) => ActionKey::ShowKek,
            (1, 2) => ActionKey::ShowDb,
            (1, 3) => ActionKey::ShowDbx,
            (1, _) => ActionKey::ListBootEntries,
            (2, 0) => ActionKey::CreateKeyPair,
            (2, 2) => ActionKey::CreatePkEsl,
            (3, 0) => ActionKey::RegisterPkFile,
            (3, 1) => ActionKey::RegisterKekFile,
            (3, 2) => ActionKey::RegisterDbFile,
            (3, _) => ActionKey::RegisterDbxFile,
            (4, 0) => ActionKey::SignBootloader,
            (4, _) => ActionKey::RegisterBootEntry,
            _ => ActionKey::RefreshStatus,
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self {
            focus: FocusPane::Segments,
            selected_segment: 0,
            selected_action: [0; 5],
            details_index: 0,
            input_mode: false,
            logs: Vec::new(),
            last_action: "None".to_string(),
            log_scroll: 0,
            create_key_pair_name: String::new(),
            create_key_pair_prefix: String::new(),
            esl_source_file: String::new(),
            esl_dest_file: String::new(),
            register_pk_path: String::new(),
            register_kek_path: String::new(),
            register_db_path: String::new(),
            register_dbx_path: String::new(),
            bootloader_path: String::new(),
        }
    }
}
