//! Dashboard page handler.

use axum::response::Html;

/// The dashboard HTML content, embedded at compile time.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// GET / - Returns the VIP dashboard page.
pub async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}
