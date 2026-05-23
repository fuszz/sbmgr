pub enum Action {
    Quit,
    Refresh,
    NextFocus,
    Submit,
    Backspace,
    Delete,
    Left,
    Right,
    MoveUp,
    MoveDown,
    Char(char),
    None,
}