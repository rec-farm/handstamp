//! Relying parties ("apps"): validation, storage with sealed secrets, the declared clients file and
//! Handstamp's own console client (docs/PLAN.md §1.3).

use std::{collections::HashMap, path::Path, sync::LazyLock};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::Row;
use url::Url;
use uuid::Uuid;

use crate::{
    audit::{Actor, Entry},
    crypto::{self, Purpose},
    db::{iso, iso_opt},
};

pub const CONSOLE_CLIENT_ID: &str = "handstamp-console";
pub const SUPPORTED_SCOPES: [&str; 5] = ["openid", "profile", "email", "groups", "offline_access"];
pub const AUTH_METHODS: [&str; 3] = ["client_secret_basic", "client_secret_post", "none"];

static CLIENT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{1,63}$").unwrap());
pub static GROUP_SLUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._:-]{0,63}$").unwrap());
static SECRET_ENV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]*$").unwrap());

/// `*.localhost` is loopback too (RFC 6761 §6.3), so local dev servers can keep named URLs.
fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]") || host.ends_with(".localhost")
}

/// Exact-match redirect URIs only: absolute https URLs (http only on loopback, RFC 8252), no
/// wildcards, no fragments, no embedded credentials.
pub fn redirect_uri_problem(value: &str) -> Option<&'static str> {
    if value.contains('*') {
        return Some("Wildcards are not allowed. Register each URI exactly.");
    }
    let Ok(url) = Url::parse(value) else {
        return Some("Use an absolute URL, such as https://app.example.com/callback.");
    };
    let host = match url.host() {
        Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    };
    if url.scheme() == "http" && !is_loopback(&host) {
        return Some("Use https://. Plain http:// is only allowed for localhost and *.localhost.");
    }
    if url.scheme() != "https" && url.scheme() != "http" {
        return Some("Only https:// URLs are supported.");
    }
    if url.fragment().is_some() {
        return Some("Remove the #fragment. Redirect URIs cannot have one.");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("Remove the credentials from the URL.");
    }
    None
}

/// What an admin or the clients file declares about an app.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDefinition {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub first_party: bool,
    #[serde(default = "yes")]
    pub require_pkce: bool,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Only members of this group (by slug) may sign in to the app (R7).
    #[serde(default)]
    pub required_group: Option<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_auth_method() -> String {
    "client_secret_basic".into()
}
fn yes() -> bool {
    true
}

/// A validation problem: the field path (as zod printed it) and a message for people.
#[derive(Debug)]
pub struct Invalid {
    pub field: String,
    pub message: String,
}

impl Invalid {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl ClientDefinition {
    /// Parses and validates, trimming the name like the old schema did. Reports the first problem.
    pub fn parse(value: &Value) -> Result<Self, Invalid> {
        let mut def: ClientDefinition = serde_json::from_value(value.clone()).map_err(|e| {
            let text = e.to_string();
            let field = ["clientId", "name", "redirectUris"]
                .into_iter()
                .find(|f| text.contains(&format!("`{f}`")))
                .unwrap_or("");
            Invalid::new(field, "Some of the details sent were not valid.")
        })?;
        def.name = def.name.trim().to_string();
        def.validate()?;
        Ok(def)
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        if !CLIENT_ID.is_match(&self.client_id) {
            return Err(Invalid::new(
                "clientId",
                "Use 2–64 lowercase letters, digits, dots, dashes or underscores.",
            ));
        }
        if self.name.is_empty() {
            return Err(Invalid::new("name", "Give the app a name."));
        }
        if self.name.chars().count() > 80 {
            return Err(Invalid::new("name", "Use at most 80 characters."));
        }
        if self.redirect_uris.is_empty() {
            return Err(Invalid::new("redirectUris", "Add at least one redirect URI."));
        }
        for (i, uri) in self.redirect_uris.iter().enumerate() {
            if let Some(problem) = redirect_uri_problem(uri) {
                return Err(Invalid::new(format!("redirectUris.{i}"), problem));
            }
        }
        for (i, uri) in self.post_logout_redirect_uris.iter().enumerate() {
            if let Some(problem) = redirect_uri_problem(uri) {
                return Err(Invalid::new(format!("postLogoutRedirectUris.{i}"), problem));
            }
        }
        for (i, scope) in self.scopes.iter().enumerate() {
            if !SUPPORTED_SCOPES.contains(&scope.as_str()) {
                return Err(Invalid::new(format!("scopes.{i}"), format!("Unknown scope {scope}.")));
            }
        }
        if !AUTH_METHODS.contains(&self.token_endpoint_auth_method.as_str()) {
            return Err(Invalid::new(
                "tokenEndpointAuthMethod",
                "Unknown token endpoint auth method.",
            ));
        }
        if let Some(uri) = &self.backchannel_logout_uri
            && let Some(problem) = redirect_uri_problem(uri)
        {
            return Err(Invalid::new("backchannelLogoutUri", problem));
        }
        if let Some(group) = &self.required_group
            && !GROUP_SLUG.is_match(group)
        {
            return Err(Invalid::new(
                "requiredGroup",
                "Use lowercase letters, digits, dots, dashes, colons or underscores.",
            ));
        }
        if !self.scopes.iter().any(|s| s == "openid") {
            return Err(Invalid::new("scopes", "Scopes must include openid."));
        }
        if self.is_public() && !self.require_pkce {
            return Err(Invalid::new("requirePkce", "Public clients always require PKCE."));
        }
        Ok(())
    }

    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none"
    }
}

/// Handstamp's own account and admin UI is a first-party client of itself.
pub fn console_client(issuer_origin: &str) -> ClientDefinition {
    ClientDefinition {
        client_id: CONSOLE_CLIENT_ID.into(),
        name: "Handstamp".into(),
        redirect_uris: vec![format!("{issuer_origin}/console/callback")],
        post_logout_redirect_uris: vec![format!("{issuer_origin}/signed-out")],
        scopes: vec!["openid".into(), "profile".into(), "email".into(), "groups".into()],
        token_endpoint_auth_method: "client_secret_basic".into(),
        first_party: true,
        require_pkce: true,
        backchannel_logout_uri: None,
        required_group: None,
    }
}

pub fn console_secret(root: &[u8]) -> String {
    crypto::b64url(&crypto::derive_key(root, Purpose::ConsoleClient))
}

/// Client secrets are generated, never chosen: 32 random bytes, shown once (S10).
pub fn new_client_secret() -> String {
    format!("hs_sec_{}", crypto::random_token(32))
}

/// A client as the protocol sees it. Disabled clients never get this far.
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub name: String,
    pub secret: Option<String>,
    pub auth_method: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub first_party: bool,
    pub require_pkce: bool,
    pub backchannel_logout_uri: Option<String>,
    pub required_group_id: Option<Uuid>,
}

impl Client {
    pub fn is_public(&self) -> bool {
        self.auth_method == "none"
    }

    /// PKCE S256 is required unless a confidential client opted out (only conformance test clients).
    pub fn pkce_required(&self) -> bool {
        self.is_public() || self.require_pkce
    }

    /// Clients that may hold offline_access are the ones allowed the refresh_token grant.
    pub fn refresh_allowed(&self) -> bool {
        self.scopes.iter().any(|s| s == "offline_access")
    }

    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.client_id
        } else {
            &self.name
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientRow {
    pub client_id: String,
    pub source: String,
    pub name: String,
    pub secret_enc: Option<Vec<u8>>,
    pub auth_method: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub first_party: bool,
    pub require_pkce: bool,
    pub backchannel_logout_uri: Option<String>,
    pub enabled: bool,
    pub required_group_id: Option<Uuid>,
    pub secret_rotated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "client_id, source, name, client_secret_enc, token_endpoint_auth_method, redirect_uris, \
     post_logout_redirect_uris, allowed_scopes, first_party, require_pkce, backchannel_logout_uri, enabled, \
     required_group_id, secret_rotated_at, created_at, updated_at";

impl From<&Row> for ClientRow {
    fn from(r: &Row) -> Self {
        Self {
            client_id: r.get(0),
            source: r.get(1),
            name: r.get(2),
            secret_enc: r.get(3),
            auth_method: r.get(4),
            redirect_uris: r.get(5),
            post_logout_redirect_uris: r.get(6),
            scopes: r.get(7),
            first_party: r.get(8),
            require_pkce: r.get(9),
            backchannel_logout_uri: r.get(10),
            enabled: r.get(11),
            required_group_id: r.get(12),
            secret_rotated_at: r.get(13),
            created_at: r.get(14),
            updated_at: r.get(15),
        }
    }
}

impl ClientRow {
    /// The admin view: the definition plus bookkeeping. Never the secret.
    pub fn view(&self, required_group: Option<String>) -> Value {
        let mut def = json!({
            "clientId": self.client_id,
            "name": self.name,
            "redirectUris": self.redirect_uris,
            "postLogoutRedirectUris": self.post_logout_redirect_uris,
            "scopes": self.scopes,
            "tokenEndpointAuthMethod": self.auth_method,
            "firstParty": self.first_party,
            "requirePkce": self.require_pkce,
        });
        if let Some(uri) = &self.backchannel_logout_uri {
            def["backchannelLogoutUri"] = json!(uri);
        }
        if let Some(group) = required_group {
            def["requiredGroup"] = json!(group);
        }
        def["source"] = json!(self.source);
        def["enabled"] = json!(self.enabled);
        def["hasSecret"] = json!(self.secret_enc.is_some());
        def["secretRotatedAt"] = iso_opt(self.secret_rotated_at);
        def["createdAt"] = json!(iso(self.created_at));
        def["updatedAt"] = json!(iso(self.updated_at));
        def
    }
}

#[derive(Debug, thiserror::Error)]
#[error("this client is read-only")]
pub struct ReadOnly;

#[derive(Deserialize)]
struct ClientsFile {
    clients: Vec<Value>,
}

pub struct Clients {
    pool: Pool,
    key: [u8; 32],
}

impl Clients {
    pub fn new(pool: Pool, root: &[u8]) -> Self {
        Self {
            pool,
            key: crypto::derive_key(root, Purpose::ClientSecrets),
        }
    }

    /// The client for the protocol. Disabled or unknown clients don't exist as far as it's concerned.
    pub async fn load(&self, client_id: &str) -> Result<Option<Client>> {
        let db = self.pool.get().await?;
        let row = db
            .query_opt(
                &format!("SELECT {COLUMNS} FROM oidc_clients WHERE client_id = $1 AND enabled"),
                &[&client_id],
            )
            .await?;
        let Some(row) = row.as_ref().map(ClientRow::from) else {
            return Ok(None);
        };
        let secret = match &row.secret_enc {
            Some(sealed) => Some(crypto::open_string(&self.key, sealed, &row.client_id)?),
            None => None,
        };
        Ok(Some(Client {
            client_id: row.client_id,
            name: row.name,
            secret,
            auth_method: row.auth_method,
            redirect_uris: row.redirect_uris,
            post_logout_redirect_uris: row.post_logout_redirect_uris,
            scopes: row.scopes,
            first_party: row.first_party,
            require_pkce: row.require_pkce,
            backchannel_logout_uri: row.backchannel_logout_uri,
            required_group_id: row.required_group_id,
        }))
    }

    /// A declared client may name a group that doesn't exist yet; create it so a config file works
    /// on a fresh instance.
    async fn group_id(db: &impl GenericClient, slug: Option<&str>) -> Result<Option<Uuid>> {
        let Some(slug) = slug else { return Ok(None) };
        db.execute(
            "INSERT INTO groups (slug, name) VALUES ($1, $1) ON CONFLICT DO NOTHING",
            &[&slug],
        )
        .await?;
        Ok(Some(
            db.query_one("SELECT id FROM groups WHERE slug = $1", &[&slug])
                .await?
                .get(0),
        ))
    }

    pub async fn upsert(&self, def: &ClientDefinition, secret: Option<&str>, source: &str) -> Result<()> {
        let public = def.is_public();
        if !public && secret.is_none_or(|s| s.len() < 32) {
            bail!("Client {} needs a secret of at least 32 characters", def.client_id);
        }
        let sealed = if public {
            None
        } else {
            Some(crypto::seal(&self.key, secret.unwrap().as_bytes(), &def.client_id))
        };
        let db = self.pool.get().await?;
        let group = Self::group_id(&db, def.required_group.as_deref()).await?;
        db.execute(
            "INSERT INTO oidc_clients (client_id, source, name, client_secret_enc, token_endpoint_auth_method, redirect_uris, \
               post_logout_redirect_uris, allowed_scopes, first_party, require_pkce, backchannel_logout_uri, required_group_id, enabled, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true, now()) \
             ON CONFLICT (client_id) DO UPDATE SET source = $2, name = $3, client_secret_enc = $4, token_endpoint_auth_method = $5, \
               redirect_uris = $6, post_logout_redirect_uris = $7, allowed_scopes = $8, first_party = $9, require_pkce = $10, \
               backchannel_logout_uri = $11, required_group_id = $12, enabled = true, updated_at = now()",
            &[
                &def.client_id,
                &source,
                &def.name,
                &sealed,
                &def.token_endpoint_auth_method,
                &def.redirect_uris,
                &def.post_logout_redirect_uris,
                &def.scopes,
                &def.first_party,
                &def.require_pkce,
                &def.backchannel_logout_uri,
                &group,
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<ClientRow>> {
        let db = self.pool.get().await?;
        Ok(db
            .query(&format!("SELECT {COLUMNS} FROM oidc_clients ORDER BY name"), &[])
            .await?
            .iter()
            .map(ClientRow::from)
            .collect())
    }

    pub async fn get(&self, client_id: &str) -> Result<Option<ClientRow>> {
        let db = self.pool.get().await?;
        Ok(db
            .query_opt(
                &format!("SELECT {COLUMNS} FROM oidc_clients WHERE client_id = $1"),
                &[&client_id],
            )
            .await?
            .as_ref()
            .map(ClientRow::from))
    }

    /// Admins edit only clients they created here; file and built-in clients are read-only.
    async fn editable(&self, client_id: &str) -> Result<Option<ClientRow>> {
        let row = self.get(client_id).await?;
        if row.as_ref().is_some_and(|r| r.source != "db") {
            return Err(ReadOnly.into());
        }
        Ok(row)
    }

    /// Ok(None) when the client ID is taken. The secret is returned once, here.
    pub async fn create(&self, def: &ClientDefinition) -> Result<Option<Option<String>>> {
        if self.get(&def.client_id).await?.is_some() {
            return Ok(None);
        }
        let secret = (!def.is_public()).then(new_client_secret);
        self.upsert(def, secret.as_deref(), "db").await?;
        Ok(Some(secret))
    }

    /// Keeps the current secret unless the auth method changes to or from public.
    pub async fn update(&self, def: &ClientDefinition) -> Result<Option<Option<String>>> {
        let Some(row) = self.editable(&def.client_id).await? else {
            return Ok(None);
        };
        let was_public = row.auth_method == "none";
        let mut new_secret = None;
        let secret = if def.is_public() {
            None
        } else if was_public {
            new_secret = Some(new_client_secret());
            new_secret.clone()
        } else {
            Some(crypto::open_string(
                &self.key,
                row.secret_enc.as_deref().unwrap_or_default(),
                &row.client_id,
            )?)
        };
        self.upsert(def, secret.as_deref(), "db").await?;
        if !row.enabled {
            self.set_enabled(&def.client_id, false).await?;
        }
        Ok(Some(new_secret))
    }

    /// Replaces the secret at once: the old one stops working immediately.
    pub async fn rotate_secret(&self, client_id: &str) -> Result<Option<String>> {
        let Some(row) = self.editable(client_id).await? else {
            return Ok(None);
        };
        if row.auth_method == "none" {
            return Ok(None);
        }
        let secret = new_client_secret();
        let sealed = crypto::seal(&self.key, secret.as_bytes(), client_id);
        let db = self.pool.get().await?;
        db.execute(
            "UPDATE oidc_clients SET client_secret_enc = $2, secret_rotated_at = now(), updated_at = now() WHERE client_id = $1",
            &[&client_id, &sealed],
        )
        .await?;
        Ok(Some(secret))
    }

    pub async fn set_enabled(&self, client_id: &str, enabled: bool) -> Result<bool> {
        self.editable(client_id).await?;
        let db = self.pool.get().await?;
        Ok(db
            .execute(
                "UPDATE oidc_clients SET enabled = $2, updated_at = now() WHERE client_id = $1",
                &[&client_id, &enabled],
            )
            .await?
            > 0)
    }

    /// Declared clients are synced at boot and read-only in the UI. A client removed from the file
    /// is disabled rather than deleted, so its audit trail stays intact.
    pub async fn sync_file(&self, path: &Path, env: &HashMap<String, String>) -> Result<Vec<String>> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("can't read {}", path.display()))?;
        let file: ClientsFile = serde_json::from_str(&raw).context("HANDSTAMP_CLIENTS_FILE is not valid JSON")?;
        let mut ids = Vec::new();
        for (i, entry) in file.clients.iter().enumerate() {
            let def = ClientDefinition::parse(entry).map_err(|p| {
                anyhow::anyhow!(
                    "HANDSTAMP_CLIENTS_FILE is invalid:\n  clients.{i}.{}: {}",
                    p.field,
                    p.message
                )
            })?;
            let secret_env = entry.get("secretEnv").and_then(Value::as_str);
            if let Some(name) = secret_env
                && !SECRET_ENV.is_match(name)
            {
                bail!("HANDSTAMP_CLIENTS_FILE is invalid:\n  clients.{i}.secretEnv: Use an environment variable name");
            }
            let secret = secret_env.and_then(|name| env.get(name)).filter(|s| !s.is_empty());
            if !def.is_public() && secret.is_none() {
                bail!(
                    "Client {} reads its secret from {}, which is not set",
                    def.client_id,
                    secret_env.unwrap_or("(no secretEnv)")
                );
            }
            self.upsert(&def, secret.map(String::as_str), "file").await?;
            ids.push(def.client_id.clone());
            Entry::new("client.synced", Actor::System)
                .target("client", &def.client_id)
                .client(&def.client_id)
                .write(&self.pool.get().await?)
                .await?;
        }
        let db = self.pool.get().await?;
        let removed = db
            .query(
                "UPDATE oidc_clients SET enabled = false, updated_at = now() \
                 WHERE source = 'file' AND enabled AND NOT (client_id = ANY($1)) RETURNING client_id",
                &[&ids],
            )
            .await?;
        for row in removed {
            let client_id: String = row.get(0);
            Entry::new("client.disabled", Actor::System)
                .target("client", &client_id)
                .client(&client_id)
                .meta(json!({ "reason": "removed_from_file" }))
                .write(&db)
                .await?;
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: Value) -> Result<ClientDefinition, Invalid> {
        ClientDefinition::parse(&value)
    }

    #[test]
    fn redirect_uris_are_exact_and_safe() {
        assert!(redirect_uri_problem("https://app.example.com/cb").is_none());
        assert!(redirect_uri_problem("http://localhost:3000/cb").is_none());
        assert!(redirect_uri_problem("http://app.localhost:1355/cb").is_none());
        assert!(redirect_uri_problem("http://127.0.0.1/cb").is_none());
        assert!(redirect_uri_problem("http://[::1]/cb").is_none());
        assert!(
            redirect_uri_problem("http://app.example.com/cb")
                .unwrap()
                .contains("https")
        );
        assert!(
            redirect_uri_problem("https://*.example.com/cb")
                .unwrap()
                .contains("Wildcards")
        );
        assert!(
            redirect_uri_problem("https://app.example.com/cb#x")
                .unwrap()
                .contains("fragment")
        );
        assert!(
            redirect_uri_problem("https://u:p@app.example.com/cb")
                .unwrap()
                .contains("credentials")
        );
        assert!(redirect_uri_problem("/cb").unwrap().contains("absolute"));
        assert!(
            redirect_uri_problem("ftp://example.com/cb")
                .unwrap()
                .contains("Only https")
        );
    }

    #[test]
    fn applies_defaults() {
        let def =
            parse(json!({ "clientId": "app", "name": " App ", "redirectUris": ["https://a.example/cb"] })).unwrap();
        assert_eq!(def.name, "App");
        assert_eq!(def.scopes, ["openid", "profile", "email"]);
        assert_eq!(def.token_endpoint_auth_method, "client_secret_basic");
        assert!(def.require_pkce && !def.first_party);
    }

    #[test]
    fn reports_the_first_problem_with_its_field() {
        let err = parse(json!({ "clientId": "A", "name": "x", "redirectUris": ["https://a.example/cb"] })).unwrap_err();
        assert_eq!(err.field, "clientId");
        let err =
            parse(json!({ "clientId": "app", "name": "x", "redirectUris": ["http://evil.example/cb"] })).unwrap_err();
        assert_eq!(err.field, "redirectUris.0");
        let err = parse(
            json!({ "clientId": "app", "name": "x", "redirectUris": ["https://a.example/cb"], "scopes": ["email"] }),
        )
        .unwrap_err();
        assert_eq!(
            (err.field.as_str(), err.message.as_str()),
            ("scopes", "Scopes must include openid.")
        );
        let err = parse(json!({
            "clientId": "app", "name": "x", "redirectUris": ["https://a.example/cb"],
            "tokenEndpointAuthMethod": "none", "requirePkce": false
        }))
        .unwrap_err();
        assert_eq!(err.field, "requirePkce");
        let err = parse(json!({ "clientId": "app", "redirectUris": ["https://a.example/cb"] })).unwrap_err();
        assert_eq!(err.field, "name");
    }

    #[test]
    fn console_secret_is_derived() {
        assert_eq!(console_secret(&[7; 32]), console_secret(&[7; 32]));
        assert_ne!(console_secret(&[7; 32]), console_secret(&[8; 32]));
    }
}
