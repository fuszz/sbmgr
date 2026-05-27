use crossterm::event::{self, KeyCode};

use crate::tui::action::Action;

pub fn read_action() -> anyhow::Result<Action> {
    match event::read()? {
        event::Event::Key(key) => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Ok(Action::Quit),
            KeyCode::Char('r') => Ok(Action::Refresh),
            KeyCode::Up => Ok(Action::MoveUp),
            KeyCode::Down => Ok(Action::MoveDown),
            _ => Ok(Action::None),
        },
        _ => Ok(Action::None),
    }
}