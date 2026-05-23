use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    style::{Style, Modifier},
};

use crate::tui::app::{FocusArea, TuiApp};
struct Areas {
    menu: Rect,
    workspace: Rect,
    footer:  Rect,
}


fn layout(area: Rect) -> Areas {

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28),
            Constraint::Min(1),
        ])
        .split(root[0]);

    Areas {
        menu: main[0],
        workspace: main[1],
        footer: root[1],
    }

}

fn render_workspace(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let workspace_title = match app.focus {
        FocusArea::Workspace => String::from(app.current_section_title().to_owned() + " [active]"),
        FocusArea::Menu => String::from(app.current_section_title()),
    };

    let mut workspace_text = app.console_log.join("\n");
    if !workspace_text.is_empty() {
        workspace_text.push('\n');
    }

    let workspace = Paragraph::new(workspace_text)
        .wrap(Wrap { trim: false })
        .block(Block::default().title(workspace_title).borders(Borders::ALL));

    frame.render_widget(workspace, area);
}

fn render_menu(frame: &mut Frame, area: Rect, app: &mut TuiApp) {
    let items: Vec<ListItem> = app
        .menu_items
        .iter()
        .map(|i| ListItem::new(*i))
        .collect();

    let title = match app.focus {
        FocusArea::Menu => "Menu [active]",
        FocusArea::Workspace => "Menu",
    };

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default().add_modifier(Modifier::BOLD)
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut app.menu_state);
}

fn render_footer(frame: &mut Frame, area: Rect) {
    let par = Paragraph::new("Tab: switch focus, ");
    frame.render_widget(par, area);
}

pub fn draw(frame: &mut Frame, app: &mut TuiApp) {
    let areas = layout(frame.area());
    render_menu(frame, areas.menu, app);
    render_workspace(frame, areas.workspace, app);
    render_footer(frame, areas.footer);
}
