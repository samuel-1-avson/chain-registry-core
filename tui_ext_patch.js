const fs = require('fs');
const path = 'f:/project/chain-registry/chain-registry/crates/cli/src/explorer_tui.rs';
let content = fs.readFileSync(path, 'utf8');

// 1. Add fields to App
if (!content.includes('bridge_anchors:')) {
    content = content.replace(
        /faucet: FaucetView,/,
        `faucet: FaucetView,
    bridge_anchors: Vec<serde_json::Value>,
    metrics_history: Vec<serde_json::Value>,
    search_results: Vec<serde_json::Value>,`
    );
}

// 2. Add App initialization for new fields
if (!content.includes('bridge_anchors: Vec::new()')) {
    content = content.replace(
        /faucet: FaucetView::new[^}]+,\n\s*\}/m,
        `faucet: FaucetView::new(
                std::env::var("CREG_FAUCET_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8082".into())
                    .trim_end_matches('/')
                    .to_string(),
            ),
            bridge_anchors: Vec::new(),
            metrics_history: Vec::new(),
            search_results: Vec::new(),
        }`
    );
}

// 3. Update draw_main_content to call the functions
content = content.replace(
    /        View::Search => draw_help\(f, app, area\), \/\/ Fallback to help for stubs\n        View::AddressDetail => draw_help\(f, app, area\),\n        View::Bridge => draw_help\(f, app, area\),\n        View::Metrics => draw_help\(f, app, area\),/,
    `        View::Search => draw_search(f, app, area),
        View::AddressDetail => draw_address(f, app, area),
        View::Bridge => draw_bridge(f, app, area),
        View::Metrics => draw_metrics(f, app, area),`
);

// 4. Append drawing functions and placeholder fetchers
const additions = `
// ============================================================================
// SPRINT 4 TUI PARITY EXTENSIONS
// ============================================================================

fn draw_search(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" SEARCH (Type / to start, Enter to execute) ")
        .border_style(Style::default().fg(Theme::accent()));

    let query_display = format!("Query: {}", app.search_query);
    let mut text_lines = vec![
        Line::from(vec![
            Span::styled("Press / to enter search, type query, hit enter (mocked).", Style::default().fg(Theme::text_dim())),
        ]),
        Line::from(""),
        Line::from(Span::styled(&query_display, Style::default().fg(Theme::highlight()))),
        Line::from(""),
        Line::from(Span::styled(format!("Found {} results (Not hooked up to node api yet in TUI)", app.search_results.len()), Style::default().fg(Theme::text()))),
    ];

    let paragraph = Paragraph::new(text_lines)
        .block(block)
        .alignment(Alignment::Left);
    f.render_widget(paragraph, area);
}

fn draw_address(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" ADDRESS DETAIL ")
        .border_style(Style::default().fg(Theme::accent()));
    let text = Paragraph::new("Address details will appear here. Navigate via Search.")
        .block(block)
        .style(Style::default().fg(Theme::text_dim()));
    f.render_widget(text, area);
}

fn draw_bridge(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" L1 BRIDGE ANCHORS ")
        .border_style(Style::default().fg(Theme::primary()));
    let text = vec![
        Line::from(format!("Bridge Status: {}", app.stats.bridge_status)),
        Line::from(format!("Latest L1 Block: {}", app.stats.l1_block)),
        Line::from(format!("Anchor count in memory: {}", app.bridge_anchors.len())),
    ];
    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Theme::text()));
    f.render_widget(paragraph, area);
}

fn draw_metrics(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CHAIN METRICS ")
        .border_style(Style::default().fg(Theme::success()));
        
    let text = vec![
        Line::from(Span::styled("Live metrics tracking coming in Sprint 5", Style::default().fg(Theme::text_dim()))),
        Line::from(format!("TPS History length: {}", app.tps_history.len())),
        Line::from(format!("Metric Accumulations: {}", app.metrics_history.len())),
    ];
    let paragraph = Paragraph::new(text)
        .block(block);
    f.render_widget(paragraph, area);
}
`;

if (!content.includes('SPRINT 4 TUI PARITY EXTENSIONS')) {
    content += additions;
}

fs.writeFileSync(path, content);
console.log('Sprint 4 TUI Ext Patched');
