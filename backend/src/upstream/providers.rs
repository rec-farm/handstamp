//! Upstream identity providers: GitHub, Google and generic OIDC issuers (docs/PLAN.md §1.4 B).

use std::collections::HashMap;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::{
    audit::{Actor, Entry},
    crypto::{self, Purpose},
    db::iso,
};

/// What an upstream provider told us about a person. Identity is (issuer, subject); the rest is
/// profile data that may change.
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub login_hint: Option<String>,
    /// GitHub orgs, when the provider restricts by org.
    pub orgs: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub id: Uuid,
    pub slug: String,
    pub kind: String,
    pub display_name: String,
    pub issuer: String,
    pub api_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub allow_signup: bool,
    pub allowed_email_domains: Vec<String>,
    pub github_allowed_orgs: Vec<String>,
    pub trust_email_verified: bool,
    pub updated_at: DateTime<Utc>,
}

impl Provider {
    /// GitHub and Google only report emails they verified. A generic issuer's email_verified is
    /// only believed when the operator says so (S13).
    pub fn trusted_email(&self, identity: &UpstreamIdentity) -> Option<String> {
        let email = identity.email.as_ref().filter(|_| identity.email_verified)?;
        if self.kind == "oidc" && !self.trust_email_verified {
            return None;
        }
        Some(email.to_lowercase())
    }

    /// May an unknown identity create an account? The reason is what the sign-in card shows.
    pub fn signup_decision(&self, identity: &UpstreamIdentity) -> Result<(), &'static str> {
        if !self.allow_signup {
            return Err("signup_closed");
        }
        if !self.allowed_email_domains.is_empty() {
            let domain = self
                .trusted_email(identity)
                .and_then(|e| e.split('@').nth(1).map(str::to_string));
            let allowed: Vec<String> = self
                .allowed_email_domains
                .iter()
                .map(|d| d.to_lowercase().trim_start_matches('@').to_string())
                .collect();
            if domain.is_none_or(|d| !allowed.contains(&d)) {
                return Err("email_domain");
            }
        }
        if self.kind == "github" && !self.github_allowed_orgs.is_empty() {
            let orgs: Vec<String> = identity
                .orgs
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|o| o.to_lowercase())
                .collect();
            if !self
                .github_allowed_orgs
                .iter()
                .any(|o| orgs.contains(&o.to_lowercase()))
            {
                return Err("org");
            }
        }
        Ok(())
    }
}

/// Upstream issuers must be https (loopback http is allowed for local testing).
pub fn upstream_url_problem(value: &str) -> Option<&'static str> {
    match Url::parse(value) {
        Err(_) => Some("is not a URL"),
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
            if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
                None
            } else {
                Some("must use https://")
            }
        }
    }
}

/// A provider as an admin or the environment declares it.
#[derive(Clone, Debug)]
pub struct Seed {
    pub slug: String,
    pub kind: String,
    pub display_name: String,
    pub issuer: String,
    pub api_url: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_signup: bool,
    pub allowed_email_domains: Vec<String>,
    pub github_allowed_orgs: Vec<String>,
    pub trust_email_verified: bool,
}

fn list(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn yes(value: Option<&String>) -> bool {
    matches!(value.map(String::as_str), Some("1" | "true"))
}

/// Providers configured through env vars (docs/PLAN.md §6.3). Unset means not seeded.
pub fn from_env(env: &HashMap<String, String>) -> Result<Vec<Seed>> {
    let get = |k: &str| env.get(k).filter(|v| !v.is_empty());
    let mut seeds = Vec::new();
    let gh = "HANDSTAMP_UPSTREAM_GITHUB_";
    if let Some(client_id) = get(&format!("{gh}CLIENT_ID")) {
        let web = get(&format!("{gh}URL"))
            .map(String::as_str)
            .unwrap_or("https://github.com")
            .trim_end_matches('/')
            .to_string();
        let api = get(&format!("{gh}API_URL")).cloned().unwrap_or_else(|| {
            if web == "https://github.com" {
                "https://api.github.com".into()
            } else {
                format!("{web}/api/v3")
            }
        });
        seeds.push(Seed {
            slug: "github".into(),
            kind: "github".into(),
            display_name: get(&format!("{gh}NAME")).cloned().unwrap_or_else(|| "GitHub".into()),
            issuer: web,
            api_url: Some(api.trim_end_matches('/').to_string()),
            client_id: client_id.clone(),
            client_secret: get(&format!("{gh}CLIENT_SECRET")).cloned(),
            scopes: vec![],
            allow_signup: yes(env.get(&format!("{gh}ALLOW_SIGNUP"))),
            allowed_email_domains: list(env.get(&format!("{gh}ALLOWED_DOMAINS"))),
            github_allowed_orgs: list(env.get(&format!("{gh}ALLOWED_ORGS"))),
            trust_email_verified: true,
        });
    }
    let google = "HANDSTAMP_UPSTREAM_GOOGLE_";
    if let Some(client_id) = get(&format!("{google}CLIENT_ID")) {
        seeds.push(Seed {
            slug: "google".into(),
            kind: "google".into(),
            display_name: get(&format!("{google}NAME"))
                .cloned()
                .unwrap_or_else(|| "Google".into()),
            issuer: "https://accounts.google.com".into(),
            api_url: None,
            client_id: client_id.clone(),
            client_secret: get(&format!("{google}CLIENT_SECRET")).cloned(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            allow_signup: yes(env.get(&format!("{google}ALLOW_SIGNUP"))),
            allowed_email_domains: list(env.get(&format!("{google}ALLOWED_DOMAINS"))),
            github_allowed_orgs: vec![],
            trust_email_verified: true,
        });
    }
    let pattern = regex::Regex::new(r"^HANDSTAMP_UPSTREAM_OIDC_([A-Z0-9_]+)_ISSUER$").unwrap();
    let mut keys: Vec<&String> = env.keys().collect();
    keys.sort();
    for key in keys {
        let Some(captures) = pattern.captures(key) else {
            continue;
        };
        let name = &captures[1];
        let prefix = format!("HANDSTAMP_UPSTREAM_OIDC_{name}_");
        let slug = name.to_lowercase().replace('_', "-");
        let scopes = list(env.get(&format!("{prefix}SCOPES")));
        seeds.push(Seed {
            slug: slug.clone(),
            kind: "oidc".into(),
            display_name: get(&format!("{prefix}NAME")).cloned().unwrap_or(slug),
            issuer: env[key].trim_end_matches('/').to_string(),
            api_url: None,
            client_id: env.get(&format!("{prefix}CLIENT_ID")).cloned().unwrap_or_default(),
            client_secret: get(&format!("{prefix}CLIENT_SECRET")).cloned(),
            scopes: if scopes.is_empty() {
                vec!["openid".into(), "email".into(), "profile".into()]
            } else {
                scopes
            },
            allow_signup: yes(env.get(&format!("{prefix}ALLOW_SIGNUP"))),
            allowed_email_domains: list(env.get(&format!("{prefix}ALLOWED_DOMAINS"))),
            github_allowed_orgs: vec![],
            trust_email_verified: yes(env.get(&format!("{prefix}TRUST_EMAIL"))),
        });
    }
    for seed in &seeds {
        let mut problems = Vec::new();
        if seed.client_id.is_empty() {
            problems.push("CLIENT_ID is missing".to_string());
        }
        if seed.client_secret.is_none() {
            problems.push("CLIENT_SECRET is missing".to_string());
        }
        if let Some(p) = upstream_url_problem(&seed.issuer) {
            problems.push(format!("issuer {p}"));
        }
        if let Some(api) = &seed.api_url
            && let Some(p) = upstream_url_problem(api)
        {
            problems.push(format!("API URL {p}"));
        }
        if !problems.is_empty() {
            bail!(
                "Upstream provider \"{}\" is misconfigured: {}",
                seed.slug,
                problems.join(", ")
            );
        }
    }
    Ok(seeds)
}

#[derive(Debug, thiserror::Error)]
#[error("this provider is read-only")]
pub struct ReadOnly;

pub struct Providers {
    pool: Pool,
    key: [u8; 32],
}

const COLUMNS: &str = "id, slug, kind, display_name, issuer, api_url, client_id, client_secret_enc, scopes, allow_signup, \
     allowed_email_domains, github_allowed_orgs, trust_email_verified, updated_at";

impl Providers {
    pub fn new(pool: Pool, root: &[u8]) -> Self {
        Self {
            pool,
            key: crypto::derive_key(root, Purpose::UpstreamSecrets),
        }
    }

    /// Env-seeded providers are synced at boot and read-only in the admin UI. One removed from the
    /// environment is disabled, not deleted, so identities that used it stay attributable.
    pub async fn sync_env(&self, env: &HashMap<String, String>) -> Result<Vec<String>> {
        let seeds = from_env(env)?;
        let db = self.pool.get().await?;
        for (index, seed) in seeds.iter().enumerate() {
            let sealed = crypto::seal(
                &self.key,
                seed.client_secret.as_deref().unwrap_or_default().as_bytes(),
                &seed.slug,
            );
            let order = index as i32;
            db.execute(
                "INSERT INTO upstream_providers (slug, kind, display_name, issuer, api_url, client_id, client_secret_enc, scopes, \
                   allow_signup, allowed_email_domains, github_allowed_orgs, trust_email_verified, source, enabled, sort_order, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'env', true, $13, now()) \
                 ON CONFLICT (slug) DO UPDATE SET kind = $2, display_name = $3, issuer = $4, api_url = $5, client_id = $6, \
                   client_secret_enc = $7, scopes = $8, allow_signup = $9, allowed_email_domains = $10, github_allowed_orgs = $11, \
                   trust_email_verified = $12, source = 'env', enabled = true, sort_order = $13, updated_at = now()",
                &[
                    &seed.slug,
                    &seed.kind,
                    &seed.display_name,
                    &seed.issuer,
                    &seed.api_url,
                    &seed.client_id,
                    &sealed,
                    &seed.scopes,
                    &seed.allow_signup,
                    &seed.allowed_email_domains,
                    &seed.github_allowed_orgs,
                    &seed.trust_email_verified,
                    &order,
                ],
            )
            .await?;
        }
        let slugs: Vec<String> = seeds.iter().map(|s| s.slug.clone()).collect();
        let removed = db
            .query(
                "UPDATE upstream_providers SET enabled = false, updated_at = now() \
                 WHERE source = 'env' AND enabled AND NOT (slug = ANY($1)) RETURNING slug",
                &[&slugs],
            )
            .await?;
        for row in removed {
            let slug: String = row.get(0);
            Entry::new("provider.disabled", Actor::System)
                .target("provider", slug)
                .meta(json!({ "reason": "removed_from_env" }))
                .write(&db)
                .await?;
        }
        Ok(slugs)
    }

    /// What the sign-in card shows.
    pub async fn list_enabled(&self) -> Result<Vec<Value>> {
        let db = self.pool.get().await?;
        Ok(db
            .query(
                "SELECT slug, kind, display_name FROM upstream_providers WHERE enabled ORDER BY sort_order, display_name",
                &[],
            )
            .await?
            .iter()
            .map(|r| json!({ "slug": r.get::<_, String>(0), "kind": r.get::<_, String>(1), "displayName": r.get::<_, String>(2) }))
            .collect())
    }

    pub async fn load(&self, slug: &str) -> Result<Option<Provider>> {
        let db = self.pool.get().await?;
        let Some(r) = db
            .query_opt(
                &format!("SELECT {COLUMNS} FROM upstream_providers WHERE slug = $1 AND enabled"),
                &[&slug],
            )
            .await?
        else {
            return Ok(None);
        };
        let slug: String = r.get(1);
        let sealed: Vec<u8> = r.get(7);
        Ok(Some(Provider {
            id: r.get(0),
            client_secret: crypto::open_string(&self.key, &sealed, &slug)?,
            slug,
            kind: r.get(2),
            display_name: r.get(3),
            issuer: r.get(4),
            api_url: r.get(5),
            client_id: r.get(6),
            scopes: r.get(8),
            allow_signup: r.get(9),
            allowed_email_domains: r.get(10),
            github_allowed_orgs: r.get(11),
            trust_email_verified: r.get(12),
            updated_at: r.get(13),
        }))
    }

    // ── admin (source 'db'; env-seeded providers stay read-only) ──

    pub async fn list(&self) -> Result<Vec<Value>> {
        let db = self.pool.get().await?;
        Ok(db
            .query(
                "SELECT id, slug, kind, display_name, issuer, api_url, client_id, scopes, allow_signup, allowed_email_domains, \
                   github_allowed_orgs, trust_email_verified, enabled, source, updated_at \
                 FROM upstream_providers ORDER BY sort_order, display_name",
                &[],
            )
            .await?
            .iter()
            .map(|r| {
                json!({
                    "id": r.get::<_, Uuid>(0),
                    "slug": r.get::<_, String>(1),
                    "kind": r.get::<_, String>(2),
                    "displayName": r.get::<_, String>(3),
                    "issuer": r.get::<_, String>(4),
                    "apiUrl": r.get::<_, Option<String>>(5),
                    "clientId": r.get::<_, String>(6),
                    "scopes": r.get::<_, Vec<String>>(7),
                    "allowSignup": r.get::<_, bool>(8),
                    "allowedEmailDomains": r.get::<_, Vec<String>>(9),
                    "githubAllowedOrgs": r.get::<_, Vec<String>>(10),
                    "trustEmailVerified": r.get::<_, bool>(11),
                    "enabled": r.get::<_, bool>(12),
                    "source": r.get::<_, String>(13),
                    "updatedAt": iso(r.get(14)),
                })
            })
            .collect())
    }

    async fn source_of(&self, slug: &str) -> Result<Option<String>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt("SELECT source FROM upstream_providers WHERE slug = $1", &[&slug])
            .await?
            .map(|r| r.get(0)))
    }

    pub async fn create(&self, seed: &Seed) -> Result<bool> {
        if self.source_of(&seed.slug).await?.is_some() {
            return Ok(false);
        }
        let sealed = crypto::seal(
            &self.key,
            seed.client_secret.as_deref().unwrap_or_default().as_bytes(),
            &seed.slug,
        );
        let db = self.pool.get().await?;
        db.execute(
            "INSERT INTO upstream_providers (slug, kind, display_name, issuer, api_url, client_id, client_secret_enc, scopes, \
               allow_signup, allowed_email_domains, github_allowed_orgs, trust_email_verified, source, sort_order) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'db', 100)",
            &[
                &seed.slug,
                &seed.kind,
                &seed.display_name,
                &seed.issuer,
                &seed.api_url,
                &seed.client_id,
                &sealed,
                &seed.scopes,
                &seed.allow_signup,
                &seed.allowed_email_domains,
                &seed.github_allowed_orgs,
                &seed.trust_email_verified,
            ],
        )
        .await?;
        Ok(true)
    }

    /// The secret is write-only: leave it out to keep the current one.
    pub async fn update(&self, seed: &Seed) -> Result<bool> {
        match self.source_of(&seed.slug).await? {
            None => return Ok(false),
            Some(source) if source != "db" => return Err(ReadOnly.into()),
            _ => {}
        }
        let sealed = seed
            .client_secret
            .as_ref()
            .map(|s| crypto::seal(&self.key, s.as_bytes(), &seed.slug));
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE upstream_providers SET kind = $2, display_name = $3, issuer = $4, api_url = $5, client_id = $6, \
               client_secret_enc = COALESCE($7, client_secret_enc), scopes = $8, allow_signup = $9, allowed_email_domains = $10, \
               github_allowed_orgs = $11, trust_email_verified = $12, updated_at = now() WHERE slug = $1",
            &[
                &seed.slug,
                &seed.kind,
                &seed.display_name,
                &seed.issuer,
                &seed.api_url,
                &seed.client_id,
                &sealed,
                &seed.scopes,
                &seed.allow_signup,
                &seed.allowed_email_domains,
                &seed.github_allowed_orgs,
                &seed.trust_email_verified,
            ],
        )
        .await?;
        Ok(true)
    }

    pub async fn set_enabled(&self, slug: &str, enabled: bool) -> Result<bool> {
        match self.source_of(slug).await? {
            None => return Ok(false),
            Some(source) if source != "db" => return Err(ReadOnly.into()),
            _ => {}
        }
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE upstream_providers SET enabled = $2, updated_at = now() WHERE slug = $1",
            &[&slug, &enabled],
        )
        .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn seeds_github_google_and_oidc() {
        let seeds = from_env(&env(&[
            ("HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID", "gh"),
            ("HANDSTAMP_UPSTREAM_GITHUB_CLIENT_SECRET", "s"),
            ("HANDSTAMP_UPSTREAM_GOOGLE_CLIENT_ID", "g"),
            ("HANDSTAMP_UPSTREAM_GOOGLE_CLIENT_SECRET", "s"),
            ("HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_ISSUER", "https://sso.corp.example/"),
            ("HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_CLIENT_ID", "c"),
            ("HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_CLIENT_SECRET", "s"),
            ("HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_TRUST_EMAIL", "1"),
        ]))
        .unwrap();
        let slugs: Vec<&str> = seeds.iter().map(|s| s.slug.as_str()).collect();
        assert_eq!(slugs, ["github", "google", "corp-sso"]);
        assert_eq!(seeds[0].api_url.as_deref(), Some("https://api.github.com"));
        assert_eq!(seeds[2].issuer, "https://sso.corp.example");
        assert!(seeds[2].trust_email_verified);
    }

    #[test]
    fn github_enterprise_api_url() {
        let seeds = from_env(&env(&[
            ("HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID", "gh"),
            ("HANDSTAMP_UPSTREAM_GITHUB_CLIENT_SECRET", "s"),
            ("HANDSTAMP_UPSTREAM_GITHUB_URL", "https://ghe.example.com/"),
        ]))
        .unwrap();
        assert_eq!(seeds[0].api_url.as_deref(), Some("https://ghe.example.com/api/v3"));
    }

    #[test]
    fn refuses_misconfigured_providers() {
        let err = from_env(&env(&[("HANDSTAMP_UPSTREAM_OIDC_X_ISSUER", "http://sso.example.com")])).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("CLIENT_ID is missing"));
        assert!(message.contains("issuer must use https://"));
    }

    fn provider(kind: &str) -> Provider {
        Provider {
            id: Uuid::nil(),
            slug: kind.into(),
            kind: kind.into(),
            display_name: kind.into(),
            issuer: String::new(),
            api_url: None,
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec![],
            allow_signup: true,
            allowed_email_domains: vec!["corp.example".into()],
            github_allowed_orgs: vec![],
            trust_email_verified: false,
            updated_at: Utc::now(),
        }
    }

    fn identity(email: &str, verified: bool) -> UpstreamIdentity {
        UpstreamIdentity {
            issuer: "i".into(),
            subject: "s".into(),
            email: Some(email.into()),
            email_verified: verified,
            name: None,
            login_hint: None,
            orgs: None,
        }
    }

    #[test]
    fn untrusted_issuers_cannot_vouch_for_email() {
        let oidc = provider("oidc");
        assert_eq!(oidc.trusted_email(&identity("a@corp.example", true)), None);
        assert_eq!(
            oidc.signup_decision(&identity("a@corp.example", true)),
            Err("email_domain")
        );
        let google = provider("google");
        assert_eq!(
            google.trusted_email(&identity("A@Corp.Example", true)).as_deref(),
            Some("a@corp.example")
        );
        assert_eq!(google.signup_decision(&identity("a@corp.example", true)), Ok(()));
        assert_eq!(
            google.signup_decision(&identity("a@corp.example", false)),
            Err("email_domain")
        );
        let closed = Provider {
            allow_signup: false,
            ..provider("google")
        };
        assert_eq!(
            closed.signup_decision(&identity("a@corp.example", true)),
            Err("signup_closed")
        );
    }

    #[test]
    fn github_orgs() {
        let gh = Provider {
            allowed_email_domains: vec![],
            github_allowed_orgs: vec!["RECIAM".into()],
            ..provider("github")
        };
        let mut who = identity("a@x.example", true);
        assert_eq!(gh.signup_decision(&who), Err("org"));
        who.orgs = Some(vec!["reciam".into()]);
        assert_eq!(gh.signup_decision(&who), Ok(()));
    }
}
