//! The SPA shell (apps/web). Server-rendered views (logout confirm, signed out, errors) reuse the
//! SPA's index.html and pass their data as escaped data-hs-* attributes on <html>: no inline
//! script, no extra cookie. In production the CSP allows 'self' plus the hash of each inline script.

use std::path::Path;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub enum Shell {
    /// Built files: index.html read once, its inline scripts hashed for the CSP.
    Static { html: String, csp: String },
    /// Development: index.html comes from the Vite dev server on every render; no CSP.
    Vite { url: String, http: reqwest::Client },
    /// No UI build (tests of the API alone): a bare document that still carries the view data.
    Bare { csp: String },
}

pub type View<'a> = &'a [(&'a str, &'a str)];

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.starts_with(|c: char| c.is_ascii_lowercase()) && key.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

pub fn inject_view(html: &str, view: View) -> String {
    if view.is_empty() {
        return html.to_string();
    }
    let attributes: String = view
        .iter()
        .filter(|(key, _)| valid_key(key))
        .map(|(key, value)| format!(" data-hs-{key}=\"{}\"", escape(value)))
        .collect();
    let lower = html.to_ascii_lowercase();
    match lower.find("<html") {
        Some(at) => format!("{}{attributes}{}", &html[..at + 5], &html[at + 5..]),
        None => html.to_string(),
    }
}

pub fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut hashes = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else { break };
        let tag = &rest[..open_end];
        let body_start = open_end + 1;
        let Some(close) = rest[body_start..].find("</script>") else { break };
        if !tag.contains("src=") {
            let body = &rest[body_start..body_start + close];
            hashes.push(script_hash(body));
        }
        rest = &rest[body_start + close..];
    }
    hashes
}

pub fn script_hash(body: &str) -> String {
    format!("'sha256-{}'", STANDARD.encode(Sha256::digest(body.as_bytes())))
}

/// For HTML pages. No form-action: the logout form posts to us and we 303 to the RP's
/// post_logout_redirect_uri, which Chrome would block under form-action 'self'.
pub fn html_csp(script_hashes: &[String]) -> String {
    [
        "default-src 'self'".to_string(),
        format!("script-src 'self' {}", script_hashes.join(" ")).trim().to_string(),
        "style-src 'self'".into(),
        "img-src 'self' data:".into(),
        "font-src 'self'".into(),
        "connect-src 'self'".into(),
        "base-uri 'none'".into(),
        "object-src 'none'".into(),
        "frame-ancestors 'none'".into(),
    ]
    .join("; ")
}

const BARE: &str = "<!doctype html><html lang=\"en\"><body></body></html>";

impl Shell {
    pub fn load(dist: &Path) -> Result<Self> {
        let index = dist.join("index.html");
        let html = std::fs::read_to_string(&index).with_context(|| format!("{} is missing", index.display()))?;
        let csp = html_csp(&inline_script_hashes(&html));
        Ok(Shell::Static { html, csp })
    }

    pub fn bare() -> Self {
        Shell::Bare { csp: html_csp(&[]) }
    }

    pub fn vite(url: String) -> Self {
        Shell::Vite { url, http: reqwest::Client::new() }
    }

    /// The CSP for every response (None in development: Vite's client needs inline scripts and eval).
    pub fn csp(&self) -> Option<&str> {
        match self {
            Shell::Static { csp, .. } | Shell::Bare { csp } => Some(csp),
            Shell::Vite { .. } => None,
        }
    }

    pub async fn render(&self, url: &str, view: View<'_>) -> String {
        match self {
            Shell::Static { html, .. } => inject_view(html, view),
            Shell::Bare { .. } => inject_view(BARE, view),
            Shell::Vite { url: base, http } => {
                // Vite serves the transformed index.html for any SPA path.
                let html = match http.get(format!("{base}{url}")).header("accept", "text/html").send().await {
                    Ok(response) => response.text().await.unwrap_or_else(|_| BARE.into()),
                    Err(_) => BARE.into(),
                };
                inject_view(&html, view)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_escaped_view_data_on_html() {
        let html = inject_view("<!doctype html><html lang=\"en\"><body></body></html>", &[
            ("view", "logout"),
            ("client", "\"><script>x</script>"),
            ("Bad", "x"),
        ]);
        assert!(html.contains(r#"<html data-hs-view="logout" data-hs-client="&quot;&gt;&lt;script&gt;x&lt;/script&gt;" lang="en">"#));
        assert!(!html.contains("data-hs-Bad"));
    }

    #[test]
    fn hashes_inline_scripts_only() {
        let html = r#"<script>a()</script><script type="module" src="/assets/x.js"></script><script>b()</script>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], format!("'sha256-{}'", STANDARD.encode(Sha256::digest(b"a()"))));
    }

    #[test]
    fn csp_matches_the_node_server() {
        assert_eq!(
            html_csp(&["'sha256-x'".into()]),
            "default-src 'self'; script-src 'self' 'sha256-x'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
        );
    }
}
