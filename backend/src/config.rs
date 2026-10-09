//! Settings from the environment, with the rules and messages of the former env.ts. Problems are
//! reported by variable name only: values may be secrets.

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Result, bail};
use ipnet::IpNet;
use url::Url;

use crate::crypto::parse_root_key;

#[derive(Clone, Debug)]
pub enum TrustProxy {
    Off,
    Hops(usize),
    Addrs(Vec<IpNet>),
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub issuer: Url,
    pub secret_key: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub trust_proxy: TrustProxy,
    pub instance_name: String,
    pub clients_file: Option<PathBuf>,
    pub session_max_days: u64,
    pub refresh_token_days: u64,
    pub access_token_minutes: u64,
    pub id_token_minutes: u64,
    pub key_rotation_days: u64,
    pub key_stage_hours: u64,
    pub allow_private_networks: bool,
    pub rate_limit_scale: f64,
    pub dev_login: bool,
    pub conformance_mode: bool,
    pub log_level: String,
    pub web_dist: PathBuf,
    /// Development: render the shell from the Vite dev server instead of a build.
    pub vite_url: Option<String>,
    /// Everything, for the clients file (`secretEnv`) and upstream providers (`HANDSTAMP_UPSTREAM_*`).
    pub env: HashMap<String, String>,
}

pub fn is_local_host(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host.ends_with(".localhost")
        || host.ends_with(".test")
}

/// Never "trust everyone": that would let any client spoof X-Forwarded-For and dodge rate limits.
pub fn parse_trust_proxy(value: &str) -> Result<TrustProxy> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(TrustProxy::Off);
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(TrustProxy::Hops(trimmed.parse()?));
    }
    let mut nets = Vec::new();
    for part in trimmed.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let net = match part.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => IpNet::from(part.parse::<std::net::IpAddr>()?),
        };
        nets.push(net);
    }
    Ok(TrustProxy::Addrs(nets))
}

struct Problems(Vec<String>);

impl Problems {
    fn add(&mut self, name: &str, message: &str) {
        self.0.push(format!("  {name}: {message}"));
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::vars().collect())
    }

    pub fn parse(env: HashMap<String, String>) -> Result<Self> {
        let mut problems = Problems(Vec::new());
        let get = |name: &str| env.get(name).map(String::as_str).filter(|v| !v.is_empty());

        let flag = |problems: &mut Problems, name: &str| match get(name) {
            None | Some("0") | Some("false") => false,
            Some("1") | Some("true") => true,
            Some(_) => {
                problems.add(name, "Use 1 or 0");
                false
            }
        };
        let positive = |problems: &mut Problems, name: &str, fallback: u64| match get(name) {
            None => fallback,
            Some(value) => match value.parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => {
                    problems.add(name, "Use a whole number greater than 0");
                    fallback
                }
            },
        };

        let production = match get("NODE_ENV").or(get("HANDSTAMP_ENV")) {
            None | Some("development") | Some("test") => false,
            Some("production") => true,
            Some(_) => {
                problems.add("NODE_ENV", "Use development, test or production");
                false
            }
        };

        let database_url = get("DATABASE_URL").unwrap_or_default().to_string();
        if database_url.is_empty() {
            problems.add("DATABASE_URL", "DATABASE_URL is required");
        }

        let issuer = match get("HANDSTAMP_ISSUER") {
            None => {
                problems.add("HANDSTAMP_ISSUER", "HANDSTAMP_ISSUER is required");
                None
            }
            Some(raw) => match Url::parse(raw) {
                Err(_) => {
                    problems.add("HANDSTAMP_ISSUER", "Invalid URL");
                    None
                }
                Ok(url) => {
                    let bare = url.path() == "/" && url.query().is_none() && url.fragment().is_none();
                    let host = url.host_str().unwrap_or_default().to_string();
                    if !bare {
                        problems.add(
                            "HANDSTAMP_ISSUER",
                            "HANDSTAMP_ISSUER must be a bare origin, such as https://id.example.com",
                        );
                        None
                    } else if url.scheme() != "https" && !is_local_host(&host) {
                        problems.add(
                            "HANDSTAMP_ISSUER",
                            "HANDSTAMP_ISSUER must use https:// (http:// is only allowed for localhost)",
                        );
                        None
                    } else {
                        Some(url)
                    }
                }
            },
        };

        let secret_key = match get("HANDSTAMP_SECRET_KEY") {
            None => {
                problems.add("HANDSTAMP_SECRET_KEY", "HANDSTAMP_SECRET_KEY is required");
                Vec::new()
            }
            Some(raw) => parse_root_key(raw).unwrap_or_else(|_| {
                problems.add(
                    "HANDSTAMP_SECRET_KEY",
                    "HANDSTAMP_SECRET_KEY must be base64 for at least 32 bytes (openssl rand -base64 32)",
                );
                Vec::new()
            }),
        };

        let port = match get("PORT") {
            None => 3000,
            Some(v) => v.parse::<u16>().ok().filter(|p| *p > 0).unwrap_or_else(|| {
                problems.add("PORT", "Use a port between 1 and 65535");
                3000
            }),
        };

        let trust_proxy = parse_trust_proxy(get("TRUST_PROXY").unwrap_or_default()).unwrap_or_else(|_| {
            problems.add(
                "TRUST_PROXY",
                "Use a hop count or a comma-separated list of addresses and CIDRs",
            );
            TrustProxy::Off
        });

        let instance_name = get("HANDSTAMP_INSTANCE_NAME")
            .map(str::trim)
            .unwrap_or("Handstamp")
            .to_string();
        if instance_name.is_empty() || instance_name.chars().count() > 60 {
            problems.add("HANDSTAMP_INSTANCE_NAME", "Use 1 to 60 characters");
        }

        let key_rotation_days = match get("KEY_ROTATION_DAYS") {
            None => 90,
            Some(v) => v.parse::<u64>().unwrap_or_else(|_| {
                problems.add("KEY_ROTATION_DAYS", "Use a whole number (0 turns rotation off)");
                90
            }),
        };

        let rate_limit_scale = match get("RATE_LIMIT_SCALE") {
            None => 1.0,
            Some(v) => v
                .parse::<f64>()
                .ok()
                .filter(|s| *s > 0.0 && *s <= 1000.0)
                .unwrap_or_else(|| {
                    problems.add("RATE_LIMIT_SCALE", "Use a number above 0 and at most 1000");
                    1.0
                }),
        };

        let log_level = get("LOG_LEVEL").unwrap_or("info").to_string();
        if !["fatal", "error", "warn", "info", "debug", "trace"].contains(&log_level.as_str()) {
            problems.add("LOG_LEVEL", "Use fatal, error, warn, info, debug or trace");
        }

        let dev_login = flag(&mut problems, "HANDSTAMP_DEV_LOGIN");
        let conformance_mode = flag(&mut problems, "HANDSTAMP_CONFORMANCE_MODE");
        // The dev test account is a back door by design. It exists only for local work and the
        // conformance suite, and never on a real hostname (S17).
        if dev_login && let Some(issuer) = &issuer {
            let local = is_local_host(issuer.host_str().unwrap_or_default());
            let allowed = if production { conformance_mode && local } else { local };
            if !allowed {
                problems.add(
                    "HANDSTAMP_DEV_LOGIN",
                    "HANDSTAMP_DEV_LOGIN only works on localhost, *.localhost or *.test issuers, and in production only with HANDSTAMP_CONFORMANCE_MODE=1",
                );
            }
        }

        let config = Self {
            database_url,
            issuer: issuer.unwrap_or_else(|| Url::parse("http://localhost").unwrap()),
            secret_key,
            host: get("HOST").unwrap_or("0.0.0.0").to_string(),
            port,
            trust_proxy,
            instance_name,
            clients_file: get("HANDSTAMP_CLIENTS_FILE").map(PathBuf::from),
            session_max_days: positive(&mut problems, "SESSION_MAX_DAYS", 14),
            refresh_token_days: positive(&mut problems, "REFRESH_TOKEN_DAYS", 14),
            access_token_minutes: positive(&mut problems, "ACCESS_TOKEN_MINUTES", 10),
            id_token_minutes: positive(&mut problems, "ID_TOKEN_MINUTES", 60),
            key_rotation_days,
            key_stage_hours: positive(&mut problems, "KEY_STAGE_HOURS", 24),
            allow_private_networks: flag(&mut problems, "ALLOW_PRIVATE_NETWORKS"),
            rate_limit_scale,
            dev_login,
            conformance_mode,
            log_level,
            web_dist: get("HANDSTAMP_WEB_DIST")
                .map(PathBuf::from)
                .unwrap_or_else(default_web_dist),
            vite_url: get("HANDSTAMP_VITE_URL").map(|v| v.trim_end_matches('/').to_string()),
            env: env.clone(),
        };

        if !problems.0.is_empty() {
            bail!(
                "Handstamp can't start. Check these settings:\n{}",
                problems.0.join("\n")
            );
        }
        Ok(config)
    }

    /// The issuer as oidc-provider printed it: the origin, no trailing slash.
    pub fn issuer_origin(&self) -> String {
        self.issuer.origin().ascii_serialization()
    }

    pub fn https(&self) -> bool {
        self.issuer.scheme() == "https"
    }

    pub fn issuer_host(&self) -> String {
        self.issuer.host_str().unwrap_or_default().to_string()
    }

    /// Retiring keys stay published while any ID token they signed can still be valid.
    pub fn rotation(&self) -> RotationPolicy {
        RotationPolicy {
            stage_hours: self.key_stage_hours,
            rotation_days: self.key_rotation_days,
            retire_after_seconds: self.id_token_minutes * 60 + 60 * 60,
        }
    }
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationPolicy {
    pub stage_hours: u64,
    /// 0 turns automatic rotation off.
    pub rotation_days: u64,
    pub retire_after_seconds: u64,
}

/// Next to the binary in the image (`/app/web/dist`), or the repo's build when run from `backend/`.
fn default_web_dist() -> PathBuf {
    for candidate in ["../apps/web/dist", "apps/web/dist", "/app/web/dist"] {
        let path = PathBuf::from(candidate);
        if path.join("index.html").exists() {
            return path;
        }
    }
    PathBuf::from("../apps/web/dist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut base: HashMap<String, String> = [
            ("DATABASE_URL", "postgres://x"),
            ("HANDSTAMP_ISSUER", "http://localhost:3000"),
            ("HANDSTAMP_SECRET_KEY", "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in pairs {
            base.insert(k.to_string(), v.to_string());
        }
        base
    }

    fn error(pairs: &[(&str, &str)]) -> String {
        Config::parse(env(pairs))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    }

    #[test]
    fn accepts_a_minimal_local_setup() {
        let config = Config::parse(env(&[])).unwrap();
        assert_eq!(config.issuer_origin(), "http://localhost:3000");
        assert!(matches!(config.trust_proxy, TrustProxy::Off));
        assert_eq!(config.port, 3000);
    }

    #[test]
    fn issuer_rules() {
        assert!(error(&[("HANDSTAMP_ISSUER", "http://id.example.com")]).contains("must use https://"));
        assert!(error(&[("HANDSTAMP_ISSUER", "https://id.example.com/path")]).contains("bare origin"));
        assert!(Config::parse(env(&[("HANDSTAMP_ISSUER", "https://id.example.com")])).is_ok());
        assert!(Config::parse(env(&[("HANDSTAMP_ISSUER", "http://handstamp.test")])).is_ok());
    }

    #[test]
    fn names_variables_but_never_values() {
        let message = error(&[("HANDSTAMP_SECRET_KEY", "c2hvcnQ=")]);
        assert!(message.contains("HANDSTAMP_SECRET_KEY"));
        assert!(!message.contains("c2hvcnQ="));
    }

    #[test]
    fn dev_login_only_on_local_issuers() {
        assert!(
            error(&[
                ("HANDSTAMP_DEV_LOGIN", "1"),
                ("HANDSTAMP_ISSUER", "https://id.example.com")
            ])
            .contains("HANDSTAMP_DEV_LOGIN")
        );
        assert!(Config::parse(env(&[("HANDSTAMP_DEV_LOGIN", "1")])).is_ok());
        assert!(error(&[("HANDSTAMP_DEV_LOGIN", "1"), ("NODE_ENV", "production")]).contains("HANDSTAMP_DEV_LOGIN"));
        assert!(
            Config::parse(env(&[
                ("HANDSTAMP_DEV_LOGIN", "1"),
                ("NODE_ENV", "production"),
                ("HANDSTAMP_CONFORMANCE_MODE", "1"),
                ("HANDSTAMP_ISSUER", "https://handstamp.test"),
            ]))
            .is_ok()
        );
    }

    #[test]
    fn trust_proxy_forms() {
        assert!(matches!(parse_trust_proxy("").unwrap(), TrustProxy::Off));
        assert!(matches!(parse_trust_proxy("2").unwrap(), TrustProxy::Hops(2)));
        match parse_trust_proxy("10.0.0.0/8, 192.168.1.1").unwrap() {
            TrustProxy::Addrs(nets) => assert_eq!(nets.len(), 2),
            other => panic!("{other:?}"),
        }
    }
}
