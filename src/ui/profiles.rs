use crate::app::App;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    // Create bordered box with centered title
    let title = format!(" Profiles[{}] ", app.available_profiles.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center);

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let header_cells = [" PROFILE"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });

    let header = Row::new(header_cells).height(1);

    let rows = app.available_profiles.iter().map(|profile| {
        let style = if profile == &app.profile {
            Style::default().fg(Color::Green)
        } else {
            Style::default()
        };

        let marker = if profile == &app.profile {
            " * "
        } else {
            "   "
        };

        Row::new(vec![
            Cell::from(format!("{}{}", marker, profile)).style(style)
        ])
    });

    let widths = [ratatui::layout::Constraint::Percentage(100)];

    let table = Table::new(rows, widths).header(header).row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

    let mut state = TableState::default();
    state.select(Some(app.profiles_selected));

    f.render_stateful_widget(table, inner_area, &mut state);
}
