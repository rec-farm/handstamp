//! Upstream sign-in routes. Filled in below.

use axum::Router;

use crate::app::App;

/// Starts linking another identity to a signed-in user: the provider URL and the state cookie.
pub async fn start_link(_app: &App, _slug: &str, _sub: &str, _console_uid: &str) -> anyhow::Result<Option<(String, String)>> {
    Ok(None)
}

pub fn routes() -> Router<App> {
    Router::new()
}
