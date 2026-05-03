use ratatui::{
    Frame,
    layout::{ Constraint, Direction, Layout, Rect},
    widgets::{ Block, Borders, List, ListItem, Paragraph },
    style::{Style, Modifier},
};

use crate::tui::app::{self, TuiApp};
struct Areas {
    menu: Rect,
    status: Rect,
    dialog: Rect,
}

fn layout(area: Rect) -> Areas {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(30),
            Constraint::Min(1),
        ])
        .split(main[0]);

    Areas {
        menu: top[0],
        status: top[1],
        dialog: main[1],
    }
}

fn render_status(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let status = Paragraph::new("Secure Boot: ON\nPK: enrolled")
        .block(Block::default().title("Stan").borders(Borders::ALL));

    frame.render_widget(status, area);
}


fn render_menu(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .menu_items
        .iter()
        .map(|i| ListItem::new(*i))
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Menu").borders(Borders::ALL))
        .highlight_style(
            Style::default().add_modifier(Modifier::BOLD)
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut app.menu_state);
}

pub fn draw(frame: &mut Frame, app: &mut TuiApp) {
    let areas = layout(frame.area());
    render_menu(frame, areas.menu, app);
    render_status(frame, areas.status, app);

}
