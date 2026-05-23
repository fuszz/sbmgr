use crossterm::event::{self, KeyCode};

use crate::tui::action::Action;

pub fn read_action() -> anyhow::Result<Action> {
    match event::read()? {
        event::Event::Key(key) => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Ok(Action::Quit),
            KeyCode::Char('r') => Ok(Action::Refresh),
            KeyCode::Tab => Ok(Action::NextFocus),
            KeyCode::Enter => Ok(Action::Submit),
            KeyCode::Backspace => Ok(Action::Backspace),
            KeyCode::Delete => Ok(Action::Delete),
            KeyCode::Left => Ok(Action::Left),
            KeyCode::Right => Ok(Action::Right),
            KeyCode::Up => Ok(Action::MoveUp),
            KeyCode::Down => Ok(Action::MoveDown),
            KeyCode::Char(c) => Ok(Action::Char(c)),
            _ => Ok(Action::None),
        },
        _ => Ok(Action::None),
    }
}