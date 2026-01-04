use crate::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, app: &App) {
    let Some(pending) = &app.pending_action else {
        return;
    };

    let area = centered_rect(50, 25, f.area());

    f.render_widget(Clear, area);

    // Determine colors based on destructive flag
    let border_color = if pending.destructive {
        Color::Red
    } else {
        Color::Yellow
    };

    let title = if pending.destructive {
        " Confirm Destructive Action "
    } else {
        " Confirm Action "
    };

    // Build the message lines
    let mut text = vec![
        Line::from(""),
        Line::from(Span::styled(
            &pending.message,
            Style::default().fg(Color::White),
        )),
        Line::from(""),
    ];

    // Add warning for destructive actions
    if pending.destructive {
        text.push(Line::from(Span::styled(
            "This action cannot be undone!",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        text.push(Line::from(""));
    }

    // Build Yes/No buttons with selection indicator
    let yes_style = if pending.selected_yes {
        Style::default()
            .fg(Color::White)
            .bg(if pending.destructive {
                Color::Red
            } else {
                Color::Green
            })
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let no_style = if !pending.selected_yes {
        Style::default()
            .fg(Color::White)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    text.push(Line::from(vec![
        Span::raw("        "),
        Span::styled(" Yes ", yes_style),
        Span::raw("     "),
        Span::styled(" No ", no_style),
    ]));

    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "← → to select, Enter to confirm, Esc to cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let block = Block::default()
        .title(title)
        .title_style(
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let paragraph = Paragraph::new(text).block(block);

    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
