use ratatui::widgets::ListState;

use crate::backend::backend::Backend;
use crate::tui::action::Action;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusArea {
    Menu,
    Workspace,
}

pub struct TuiApp {
    pub should_quit: bool,
    pub menu_state: ListState,
    pub menu_items: Vec<&'static str>,
    pub variables: Vec<String>,
    pub secure_boot_lines: Vec<String>,
    pub boot_entries_lines: Vec<String>,
    pub console_log: Vec<String>,
    pub console_input: String,
    pub console_cursor: usize,
    pub focus: FocusArea,
    pub message: Option<String>,
    pub backend: Backend,
}

impl TuiApp {
    pub fn new() -> anyhow::Result<Self> {
        let mut menu_state = ListState::default();
        menu_state.select(Some(0));
        Ok(Self {
            should_quit: false,
            menu_state: menu_state,
            menu_items: vec!["Overview", "Secure Boot", "Boot entries", "Variables", "Console"],
            variables: Vec::new(),
            secure_boot_lines: Vec::new(),
            boot_entries_lines: Vec::new(),
            console_log: vec!["Welcome. Type `help` for commands.".to_string()],
            console_input: String::new(),
            console_cursor: 0,
            focus: FocusArea::Menu,
            message: None,
            backend: Backend::new()?,
        })
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        self.variables = self.backend.list_variables()?;
        self.secure_boot_lines = self.backend.secure_boot_report()?;
        self.boot_entries_lines = self.backend.boot_entries_report()?;
        self.message = Some("Refreshed".into());
        Ok(())
    }

    pub fn current_section_title(&self) -> &'static str {
        match self.menu_state.selected().unwrap_or(0) {
            0 => "Overview",
            1 => "Secure Boot",
            2 => "Boot entries",
            3 => "Variables",
            _ => "Console",
        }
    }

    fn focus_next(&mut self) {
        self.focus = match self.focus {
            FocusArea::Menu => FocusArea::Workspace,
            FocusArea::Workspace => FocusArea::Menu,
        };
    }

    fn insert_console_char(&mut self, ch: char) {
        self.console_input.insert(self.console_cursor, ch);
        self.console_cursor += ch.len_utf8();
    }

    fn console_backspace(&mut self) {
        if self.console_cursor == 0 {
            return;
        }

        let prev = self.console_input[..self.console_cursor]
            .chars()
            .next_back()
            .map(|ch| ch.len_utf8())
            .unwrap_or(1);

        let start = self.console_cursor - prev;
        self.console_input.drain(start..self.console_cursor);
        self.console_cursor = start;
    }

    fn console_delete(&mut self) {
        if self.console_cursor >= self.console_input.len() {
            return;
        }

        let end = self.console_input[self.console_cursor..]
            .chars()
            .next()
            .map(|ch| self.console_cursor + ch.len_utf8())
            .unwrap_or(self.console_cursor);

        self.console_input.drain(self.console_cursor..end);
    }

    fn console_move_left(&mut self) {
        if self.console_cursor == 0 {
            return;
        }

        if let Some(ch) = self.console_input[..self.console_cursor].chars().next_back() {
            self.console_cursor -= ch.len_utf8();
        }
    }

    fn console_move_right(&mut self) {
        if self.console_cursor >= self.console_input.len() {
            return;
        }

        if let Some(ch) = self.console_input[self.console_cursor..].chars().next() {
            self.console_cursor += ch.len_utf8();
        }
    }

    fn push_log_lines<I>(&mut self, lines: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.console_log.extend(lines);
        if self.console_log.len() > 250 {
            let drain = self.console_log.len() - 250;
            self.console_log.drain(0..drain);
        }
    }

    fn submit_console_input(&mut self) -> anyhow::Result<()> {
        let command = self.console_input.trim().to_string();
        if command.is_empty() {
            self.console_input.clear();
            self.console_cursor = 0;
            return Ok(());
        }

        self.push_log_lines(vec![format!("> {command}")]);
        match self.backend.run_console_command(&command) {
            Ok(lines) => self.push_log_lines(lines),
            Err(err) => self.push_log_lines(vec![format!("error: {err}")]),
        }

        self.console_input.clear();
        self.console_cursor = 0;
        self.refresh()?;
        Ok(())
    }

    pub fn move_down(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i >= self.menu_items.len() - 1 { 0 } else { i + 1 }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    pub fn move_up(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i == 0 { self.menu_items.len() - 1 } else { i - 1 }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    pub fn handle_action(&mut self, action: Action) -> anyhow::Result<()> {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Refresh => self.refresh()?,
            Action::NextFocus => self.focus_next(),
            Action::Submit => {
                if self.focus == FocusArea::Workspace {
                    self.submit_console_input()?;
                }
            }
            Action::Backspace => {
                if self.focus == FocusArea::Workspace {
                    self.console_backspace();
                }
            }
            Action::Delete => {
                if self.focus == FocusArea::Workspace {
                    self.console_delete();
                }
            }
            Action::Left => {
                if self.focus == FocusArea::Workspace {
                    self.console_move_left();
                }
            }
            Action::Right => {
                if self.focus == FocusArea::Workspace {
                    self.console_move_right();
                }
            }
            Action::MoveUp => {
                if self.focus == FocusArea::Menu {
                    self.move_up();
                }
            }
            Action::MoveDown => {
                if self.focus == FocusArea::Menu {
                    self.move_down();
                }
            }
            Action::Char(c) => {
                if self.focus == FocusArea::Workspace {
                    self.insert_console_char(c);
                }
            }
            Action::None => {}
        }

        Ok(())
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let mut terminal = crate::tui::terminal::init()?;

        self.refresh()?;

        while !self.should_quit {
            terminal.draw(|frame| crate::tui::ui::draw(frame, self))?;

            let action = crate::tui::event::read_action()?;
            self.handle_action(action)?;
        }

        crate::tui::terminal::restore()?;
        Ok(())
    }
}