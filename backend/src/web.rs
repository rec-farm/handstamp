//! The SPA shell, served like apps/server/src/http/shell.ts and headers.ts: index.html read once,
//! inline script hashes computed for the CSP, the same base headers on every response.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct Shell {
    pub html: String,
    pub csp: String,
}

fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut hashes = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else { break };
        let tag = &rest[..open_end];
        let body_start = open_end + 1;
        let Some(close) = rest[body_start..].find("</script>") else {
            break;
        };
        if !tag.contains("src=") {
            let body = &rest[body_start..body_start + close];
            hashes.push(format!("'sha256-{}'", STANDARD.encode(Sha256::digest(body.as_bytes()))));
        }
        rest = &rest[body_start + close..];
    }
    hashes
}

// No form-action: the logout form posts to us and we 303 to the RP's post_logout_redirect_uri.
pub fn html_csp(script_hashes: &[String]) -> String {
    [
        "default-src 'self'".to_string(),
        format!("script-src 'self' {}", script_hashes.join(" "))
            .trim()
            .to_string(),
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

impl Shell {
    pub fn load(dist: &Path) -> Result<Self> {
        let index = dist.join("index.html");
        let html = std::fs::read_to_string(&index)
            .with_context(|| format!("{} is missing: run pnpm build", index.display()))?;
        let csp = html_csp(&inline_script_hashes(&html));
        Ok(Self { html, csp })
    }

    pub fn bare() -> Self {
        let html =
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Handstamp</title></head><body></body></html>"
                .to_string();
        Self {
            csp: html_csp(&[]),
            html,
        }
    }
}

pub fn base_headers(https: bool) -> Vec<(&'static str, &'static str)> {
    let mut headers = vec![
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
    ];
    if https {
        headers.push(("strict-transport-security", "max-age=31536000"));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_inline_scripts_only() {
        let html = r#"<script>a()</script><script type="module" src="/assets/x.js"></script><script>b()</script>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0],
            format!("'sha256-{}'", STANDARD.encode(Sha256::digest(b"a()")))
        );
    }

    #[test]
    fn csp_matches_node() {
        assert_eq!(
            html_csp(&["'sha256-x'".into()]),
            "default-src 'self'; script-src 'self' 'sha256-x'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
        );
    }
}
