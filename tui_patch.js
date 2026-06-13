const fs = require('fs')

const path = 'f:/project/chain-registry/chain-registry/crates/cli/src/explorer_tui.rs'
let content = fs.readFileSync(path, 'utf8')

// 1. Fix themes
content = content.replace(/Theme::text\(\)_DIM/g, 'Theme::text_dim()')
content = content.replace(/Theme::text\(\)_DARK/g, 'Theme::text_dark()')
content = content.replace(/Theme::TEXT_DIM/g, 'Theme::text_dim()')
content = content.replace(/Theme::TEXT_DARK/g, 'Theme::text_dark()')
content = content.replace(/Theme::TEXT/g, 'Theme::text()')
content = content.replace(/Theme::BG/g, 'Theme::bg()')
content = content.replace(/Theme::BORDER/g, 'Theme::border()')

// 2. Add Theme toggle
const themeKeyStr = "KeyCode::Char('t') | KeyCode::Char('T') => {\n            let current = IS_LIGHT_THEME.load(Ordering::Relaxed);\n            IS_LIGHT_THEME.store(!current, Ordering::Relaxed);\n            return false;\n        }"
if (!content.includes("KeyCode::Char('t')")) {
    content = content.replace(
        /KeyCode::Char\('0'\) \| KeyCode::Char\('F'\) => \{\s*app\.current_view = View::Faucet;\s*\}/,
        `KeyCode::Char('0') | KeyCode::Char('F') => {\n            app.current_view = View::Faucet;\n        }\n        ${themeKeyStr}`
    )
}

// 3. Add Views
if (!content.includes('AddressDetail')) {
    content = content.replace(
        /Faucet,\n    Help,/,
        "Faucet,\n    Search,\n    AddressDetail,\n    Bridge,\n    Metrics,\n    Help,"
    )
}

// 4. Update Header tabs to include new views (Overview Blocks Validators Packages Network Mempool Events Faucet Operator Consensus Search Bridge Metrics)
// Actually, TUI tabs in `draw_header` are rendered from a list. Let's find the `let titles = vec![ ... ]`
const newTabs = `let titles = vec![
        "Overview (1)",
        "Blocks (2)",
        "Validators (3)",
        "Packages (4)",
        "Network (5)",
        "Mempool (6)",
        "Events (7)",
        "Operator (8)",
        "Consensus (9)",
        "Faucet (0)",
        "Search (/)",
        "Bridge",
        "Metrics",
    ];`
content = content.replace(/let titles = vec!\[([\s\S]*?)\];/, newTabs)

// Map current view to tab selection
const selectionLogic = `app.selected_tab = match app.current_view {
        View::Overview => 0,
        View::Blocks | View::BlockDetail => 1,
        View::Validators | View::ValidatorDetail => 2,
        View::Packages | View::PackageDetail => 3,
        View::Network => 4,
        View::Mempool => 5,
        View::Events => 6,
        View::Operator => 7,
        View::Consensus => 8,
        View::Faucet => 9,
        View::Search | View::AddressDetail => 10,
        View::Bridge => 11,
        View::Metrics => 12,
        View::Help => 99,
    };`
content = content.replace(/app\.selected_tab = match app\.current_view \{[^}]+\};/, selectionLogic)

// Mouse click navigation (tabs and table rows)
const mouseLogic = `match mouse.kind {
        MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
            let row = mouse.row;
            if row == 2 || row == 3 || row == 4 { // Approximate header area
                match mouse.column {
                    0..=12 => app.current_view = View::Overview,
                    13..=23 => app.current_view = View::Blocks,
                    24..=38 => app.current_view = View::Validators,
                    39..=51 => app.current_view = View::Packages,
                    52..=63 => app.current_view = View::Network,
                    64..=75 => app.current_view = View::Mempool,
                    76..=86 => app.current_view = View::Events,
                    87..=99 => app.current_view = View::Operator,
                    100..=113 => app.current_view = View::Consensus,
                    114..=124 => app.current_view = View::Faucet,
                    125..=136 => { app.current_view = View::Overview; app.is_searching = true; },
                    137..=145 => app.current_view = View::Bridge,
                    146..=160 => app.current_view = View::Metrics,
                    _ => {}
                }
            } else if row >= 6 {
                // Approximate row selection based on current view
                let index = (row - 6) as usize;
                match app.current_view {
                    View::Blocks | View::Overview => {
                        if index < app.blocks.len() {
                            app.selected_block = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::BlockDetail;
                        }
                    }
                    View::Validators => {
                        if index < app.validators.len() {
                            app.selected_validator = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::ValidatorDetail;
                        }
                    }
                    View::Packages => {
                        if index < app.packages.len() {
                            app.selected_package = index;
                            app.previous_view = Some(app.current_view);
                            app.current_view = View::PackageDetail;
                        }
                    }
                    _ => {}
                }
            }
        },
        MouseEventKind::ScrollDown => match app.current_view {`

content = content.replace(/MouseEventKind::ScrollDown => match app\.current_view \{/, mouseLogic)


// Update draw_main_content
const newDrawSwitch = `        View::Search => draw_help(f, app, area), // Fallback to help for stubs
        View::AddressDetail => draw_help(f, app, area),
        View::Bridge => draw_help(f, app, area),
        View::Metrics => draw_help(f, app, area),
        View::Help => draw_help(f, app, area),`

content = content.replace(/View::Help => draw_help\(f, app, area\),/, newDrawSwitch)

fs.writeFileSync(path, content)
console.log('TUI Patched Successfully')
