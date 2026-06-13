// crates/node/src/explorer.rs
use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};

/// Serves the embedded block explorer SPA when built with `embedded-explorer`.
/// Protocol-only builds (chain-registry-core) omit the UI; run the explorer from
/// chain-registry-ops or proxy it separately.
#[cfg(feature = "embedded-explorer")]
pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    use mime_guess::from_path;
    use rust_embed::RustEmbed;

    #[derive(RustEmbed)]
    #[folder = "../../explorer/dist"]
    struct WebAssets;

    let mut path = uri.path().trim_start_matches('/').to_string();

    if path.starts_with("ui/") {
        path = path.replacen("ui/", "", 1);
    } else if path == "ui" {
        path = "index.html".to_string();
    }

    if path.is_empty() {
        path = "index.html".to_string();
    }

    match WebAssets::get(&path) {
        Some(content) => {
            let mime = from_path(&path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            if let Some(index) = WebAssets::get("index.html") {
                let mime = from_path("index.html").first_or_octet_stream();
                ([(header::CONTENT_TYPE, mime.as_ref())], index.data).into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    "404 Not Found. Build explorer/dist and enable embedded-explorer.",
                )
                    .into_response()
            }
        }
    }
}

#[cfg(not(feature = "embedded-explorer"))]
pub async fn static_handler(_uri: Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        "Explorer UI is not embedded in this node build. Use the standalone explorer app.",
    )
        .into_response()
}
