use ratatui::widgets::ListState;

use crate::backend::backend::Backend;
use crate::tui::action::Action;

pub struct TuiApp {
    pub should_quit: bool,
    pub menu_state: ListState,
    pub menu_items: Vec<&'static str>,
    pub variables: Vec<String>,
    pub secure_boot_lines: Vec<String>,
    pub message: Option<String>,
    pub backend: Backend,
}

impl TuiApp {
//     pub fn new() -> anyhow::Result<Self> {
//         let mut menu_state = ListState::default();
//         menu_state.select(Some(0));
//         Ok(Self {
//             should_quit: false,
//             menu_state: menu_state,
//             menu_items: vec!["Opcja1", "Opcja2", "Opcja3", "Opcja4"],
//             variables: Vec::new(),
//             secure_boot_lines: Vec::new(),
//             message: None,
//             backend: Backend::new()?,
//         })
//     }

//     // pub fn refresh(&mut self) -> anyhow::Result<()> {
//     //     self.variables = self.backend.list_variables()?;
//     //     self.secure_boot_lines = self.backend.secure_boot_report()?;
//     //     self.message = Some("Refreshed".into());
//     //     Ok(())
//     // }

//     pub fn move_down(&mut self) {
//         let i = match self.menu_state.selected() {
//             Some(i) => {
//                 if i >= self.menu_items.len() - 1 { 0 } else { i + 1 }
//             }
//             None => 0,
//         };
//         self.menu_state.select(Some(i));
//     }

//     pub fn move_up(&mut self) {
//         let i = match self.menu_state.selected() {
//             Some(i) => {
//                 if i == 0 { self.menu_items.len() - 1 } else { i - 1 }
//             }
//             None => 0,
//         };
//         self.menu_state.select(Some(i));
//     }

//     pub fn handle_action(&mut self, action: Action) -> anyhow::Result<()> {
//         match action {
//             Action::Quit => self.should_quit = true,
//             Action::Refresh => self.refresh()?,
//             Action::MoveUp => self.move_up(),
//             Action::MoveDown => self.move_down(),
//             Action::None => {}
//         }

//         Ok(())
//     }

//     pub fn run(&mut self) -> anyhow::Result<()> {
//         let mut terminal = crate::tui::terminal::init()?;

//         self.refresh()?;

//         while !self.should_quit {
//             terminal.draw(|frame| crate::tui::ui::draw(frame, self))?;

//             let action = crate::tui::event::read_action()?;
//             self.handle_action(action)?;
//         }

//         crate::tui::terminal::restore()?;
//         Ok(())
//     }
 }