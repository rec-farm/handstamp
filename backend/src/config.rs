use anyhow::{Context, Result, bail};
use std::{env, path::PathBuf};
use url::Url;

use crate::crypto::parse_root_key;

#[derive(Clone)]
pub struct Config {
    pub issuer: String,
    pub https: bool,
    pub database_url: String,
    pub secret_key: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub web_dist: PathBuf,
    // Any TRUST_PROXY value makes oidc-provider read X-Forwarded-Proto/Host (provider.ts).
    pub trust_proxy: bool,
}

fn local_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

// Same rules as apps/server/src/env.ts for the settings the spike reads.
pub fn issuer(value: &str) -> Result<(String, bool)> {
    let url = Url::parse(value).context("HANDSTAMP_ISSUER must be a URL")?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() || value.ends_with('/') {
        bail!("HANDSTAMP_ISSUER must be a bare origin, such as https://id.example.com");
    }
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "https" => Ok((url.origin().ascii_serialization(), true)),
        "http" if local_host(host) => Ok((url.origin().ascii_serialization(), false)),
        _ => bail!("HANDSTAMP_ISSUER must use https:// (http:// is only allowed for localhost)"),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let required = |name: &str| env::var(name).with_context(|| format!("{name} is required"));
        let (issuer, https) = issuer(&required("HANDSTAMP_ISSUER")?)?;
        Ok(Self {
            issuer,
            https,
            database_url: required("DATABASE_URL")?,
            secret_key: parse_root_key(&required("HANDSTAMP_SECRET_KEY")?)?,
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .map(|p| p.parse())
                .transpose()
                .context("PORT must be a number")?
                .unwrap_or(3000),
            trust_proxy: !env::var("TRUST_PROXY").unwrap_or_default().trim().is_empty(),
            web_dist: env::var("HANDSTAMP_WEB_DIST")
                .map(PathBuf::from)
                .unwrap_or_else(|_| "../apps/web/dist".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::issuer;

    #[test]
    fn issuer_rules_match_node() {
        assert_eq!(
            issuer("https://id.example.com").unwrap(),
            ("https://id.example.com".into(), true)
        );
        assert_eq!(
            issuer("http://localhost:3000").unwrap(),
            ("http://localhost:3000".into(), false)
        );
        assert!(issuer("http://id.example.com").is_err());
        assert!(issuer("https://id.example.com/").is_err());
        assert!(issuer("https://id.example.com/path").is_err());
    }
}
