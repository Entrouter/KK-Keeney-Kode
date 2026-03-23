// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! KK Visual Demo, Watch the Keeney Kode primitive in action.
//!
//! Run: cargo run --example visual

use std::io;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

struct App {
    input: String,
    cursor_pos: usize,
    shared_secret: String,
    encode_result: Option<EncodeResult>,
    status: String,
    encode_count: u64,
}

struct EncodeResult {
    ciphertext_hex: String,
    entropy_hex: String,
    timestamp_nanos: u128,
    commitment_hex: String,
    decoded_text: String,
    wire_size: usize,
    encode_time: Duration,
    decode_time: Duration,
    match_ok: bool,
}

impl App {
    fn new() -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            shared_secret: "kk-demo-secret-2026".into(),
            encode_result: None,
            status: "Type a message and press Enter to encode. Tab = edit secret. Esc = quit."
                .into(),
            encode_count: 0,
        }
    }

    fn do_encode(&mut self) {
        if self.input.is_empty() {
            self.status = "Nothing to encode, type something first!".into();
            return;
        }

        let secret = self.shared_secret.as_bytes();
        let plaintext = self.input.as_bytes();

        // Encode
        let t0 = Instant::now();
        let packet = match kk_crypto::encode(secret, plaintext) {
            Ok(p) => p,
            Err(e) => {
                self.status = format!("Encode error: {e}");
                return;
            }
        };
        let encode_time = t0.elapsed();

        // Serialize wire format
        let wire = packet.to_bytes();

        // Decode
        let t1 = Instant::now();
        let decoded = match kk_crypto::decode(secret, &packet) {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("Decode error: {e}");
                return;
            }
        };
        let decode_time = t1.elapsed();

        let decoded_text = String::from_utf8_lossy(&decoded).to_string();
        let match_ok = plaintext == decoded.as_slice();

        self.encode_count += 1;
        self.encode_result = Some(EncodeResult {
            ciphertext_hex: hex_encode(&packet.ciphertext),
            entropy_hex: hex_encode(&packet.entropy_snapshot.bytes),
            timestamp_nanos: packet.entropy_snapshot.timestamp_nanos,
            commitment_hex: hex_encode(&packet.commitment.mac),
            decoded_text,
            wire_size: wire.len(),
            encode_time,
            decode_time,
            match_ok,
        });
        self.status = format!(
            "#{}, Encoded & decoded in {:.1}µs + {:.1}µs | Press Enter to re-encode (new ε each time)",
            self.encode_count,
            encode_time.as_nanos() as f64 / 1000.0,
            decode_time.as_nanos() as f64 / 1000.0,
        );
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut editing_secret = false;

    loop {
        terminal.draw(|f| ui(f, &app, editing_secret))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Tab => {
                        editing_secret = !editing_secret;
                        if editing_secret {
                            app.status = "Editing shared secret. Tab to go back to message.".into();
                        } else {
                            app.status = "Type a message and press Enter to encode.".into();
                        }
                    }
                    KeyCode::Enter => {
                        if !editing_secret {
                            app.do_encode();
                        }
                    }
                    KeyCode::Backspace => {
                        let target = if editing_secret {
                            &mut app.shared_secret
                        } else {
                            &mut app.input
                        };
                        if !target.is_empty() {
                            if editing_secret {
                                target.pop();
                            } else if app.cursor_pos > 0 {
                                app.cursor_pos -= 1;
                                target.remove(app.cursor_pos);
                            }
                        }
                    }
                    KeyCode::Left => {
                        if !editing_secret && app.cursor_pos > 0 {
                            app.cursor_pos -= 1;
                        }
                    }
                    KeyCode::Right => {
                        if !editing_secret && app.cursor_pos < app.input.len() {
                            app.cursor_pos += 1;
                        }
                    }
                    KeyCode::Char(c) => {
                        if editing_secret {
                            app.shared_secret.push(c);
                        } else {
                            app.input.insert(app.cursor_pos, c);
                            app.cursor_pos += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn ui(f: &mut Frame, app: &App, editing_secret: bool) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Length(3), // secret
            Constraint::Length(3), // input
            Constraint::Min(10),   // results
            Constraint::Length(2), // status bar
        ])
        .split(f.area());

    // ─── TITLE ───────────────────────────────────────────
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "  KK ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  "),
        Span::styled(
            "Keeney Kode Visual Demo",
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::raw(" - "),
        Span::styled("KK(S) = S ⊕ ε", Style::default().fg(Color::Yellow).italic()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(title, outer[0]);

    // ─── SHARED SECRET ───────────────────────────────────
    let secret_style = if editing_secret {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let secret_block = Block::default()
        .title(Span::styled(" Shared Secret (Tab to edit) ", secret_style))
        .borders(Borders::ALL)
        .border_style(if editing_secret {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let secret_text = Paragraph::new(Line::from(vec![
        Span::raw("  "),
        Span::styled(&app.shared_secret, Style::default().fg(Color::Yellow)),
    ]))
    .block(secret_block);
    f.render_widget(secret_text, outer[1]);

    // ─── MESSAGE INPUT ───────────────────────────────────
    let input_style = if !editing_secret {
        Style::default().fg(Color::Green).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let input_block = Block::default()
        .title(Span::styled(" Message (Enter to encode) ", input_style))
        .borders(Borders::ALL)
        .border_style(if !editing_secret {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let input_text = Paragraph::new(Line::from(vec![
        Span::raw("  "),
        Span::styled(&app.input, Style::default().fg(Color::White).bold()),
    ]))
    .block(input_block);
    f.render_widget(input_text, outer[2]);

    // Cursor
    if !editing_secret {
        f.set_cursor_position((outer[2].x + 3 + app.cursor_pos as u16, outer[2].y + 1));
    }

    // ─── RESULTS ─────────────────────────────────────────
    let results_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[3]);

    // Left: Encoded
    let encode_block = Block::default()
        .title(Span::styled(
            " ⚡ Encoded Packet ",
            Style::default().fg(Color::Magenta).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let encode_content = if let Some(r) = &app.encode_result {
        let ct_display = wrap_hex(&r.ciphertext_hex, 48);
        let mut lines = vec![Line::from(vec![Span::styled(
            "  Ciphertext: ",
            Style::default().fg(Color::DarkGray),
        )])];
        for chunk in ct_display {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(chunk, Style::default().fg(Color::Magenta)),
            ]));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  Entropy ε:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(&r.entropy_hex[..16], Style::default().fg(Color::Cyan)),
            Span::styled("...", Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Timestamp:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ns", r.timestamp_nanos),
                Style::default().fg(Color::Cyan),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  HMAC:       ", Style::default().fg(Color::DarkGray)),
            Span::styled(&r.commitment_hex[..16], Style::default().fg(Color::Red)),
            Span::styled("...", Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Wire size:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} bytes", r.wire_size),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Encode:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1} µs", r.encode_time.as_nanos() as f64 / 1000.0),
                Style::default().fg(Color::Yellow),
            ),
        ]));
        Text::from(lines)
    } else {
        Text::from(vec![
            Line::raw(""),
            Line::from(Span::styled(
                "    Press Enter to encode your message...",
                Style::default().fg(Color::DarkGray).italic(),
            )),
        ])
    };
    f.render_widget(
        Paragraph::new(encode_content)
            .block(encode_block)
            .wrap(Wrap { trim: false }),
        results_layout[0],
    );

    // Right: Decoded
    let decode_block = Block::default()
        .title(Span::styled(
            " ✓ Decoded Output ",
            Style::default().fg(Color::Green).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let decode_content = if let Some(r) = &app.encode_result {
        let match_indicator = if r.match_ok {
            Span::styled(" ✓ MATCH", Style::default().fg(Color::Green).bold())
        } else {
            Span::styled(" ✗ MISMATCH!", Style::default().fg(Color::Red).bold())
        };

        Text::from(vec![
            Line::raw(""),
            Line::from(vec![Span::styled(
                "  Plaintext: ",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled(&r.decoded_text, Style::default().fg(Color::White).bold()),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  Integrity: ", Style::default().fg(Color::DarkGray)),
                match_indicator,
            ]),
            Line::from(vec![
                Span::styled("  Decode:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.1} µs", r.decode_time.as_nanos() as f64 / 1000.0),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "  Press Enter again, same message,",
                Style::default().fg(Color::DarkGray).italic(),
            )),
            Line::from(Span::styled(
                "  new ε, completely different ciphertext.",
                Style::default().fg(Color::DarkGray).italic(),
            )),
        ])
    } else {
        Text::from(vec![
            Line::raw(""),
            Line::from(Span::styled(
                "    Decoded output will appear here...",
                Style::default().fg(Color::DarkGray).italic(),
            )),
        ])
    };
    f.render_widget(
        Paragraph::new(decode_content)
            .block(decode_block)
            .wrap(Wrap { trim: false }),
        results_layout[1],
    );

    // ─── STATUS BAR ──────────────────────────────────────
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(&app.status, Style::default().fg(Color::DarkGray).italic()),
    ]));
    f.render_widget(status, outer[4]);
}

fn wrap_hex(hex: &str, width: usize) -> Vec<String> {
    hex.as_bytes()
        .chunks(width)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect()
}
