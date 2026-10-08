//! The client half of upstream sign-in. Generic OIDC issuers and Google go through `openidconnect`
//! (discovery, PKCE, nonce, ID token validation); GitHub speaks plain OAuth 2, so it is a hand-built
//! authorization code flow with PKCE plus its REST API.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use openidconnect::{
    AccessToken, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, SubjectIdentifier, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::providers::{Provider, UpstreamIdentity};
use crate::crypto::{b64url, random_token, sha256};

/// What has to survive the round trip to the provider (kept in a sealed cookie).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub state: String,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct UpstreamError {
    pub code: &'static str,
    pub message: String,
}

impl UpstreamError {
    fn failed(message: impl Into<String>) -> Self {
        Self {
            code: "upstream_failed",
            message: message.into(),
        }
    }
}

/// openidconnect needs a client that never follows redirects (SSRF and code leakage).
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .user_agent("Handstamp")
        .build()
        .expect("an HTTP client")
});

/// Discovered metadata per provider and its current settings.
static METADATA: LazyLock<Mutex<HashMap<String, CoreProviderMetadata>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

async fn metadata(provider: &Provider) -> Result<CoreProviderMetadata, UpstreamError> {
    let key = format!("{}:{}", provider.id, provider.updated_at.timestamp_micros());
    if let Some(found) = METADATA.lock().unwrap().get(&key) {
        return Ok(found.clone());
    }
    let issuer =
        IssuerUrl::new(provider.issuer.clone()).map_err(|e| UpstreamError::failed(format!("bad issuer: {e}")))?;
    let discovered = CoreProviderMetadata::discover_async(issuer, &*HTTP)
        .await
        .map_err(|e| UpstreamError::failed(format!("Discovery for {} failed: {e}", provider.display_name)))?;
    METADATA.lock().unwrap().insert(key, discovered.clone());
    Ok(discovered)
}

fn scopes(provider: &Provider) -> Vec<String> {
    if provider.kind == "github" {
        let mut scopes = vec!["read:user".to_string(), "user:email".to_string()];
        if !provider.github_allowed_orgs.is_empty() {
            scopes.push("read:org".into());
        }
        return scopes;
    }
    if provider.scopes.is_empty() {
        vec!["openid".into(), "email".into(), "profile".into()]
    } else {
        provider.scopes.clone()
    }
}

fn redirect(uri: &str) -> Result<RedirectUrl, UpstreamError> {
    RedirectUrl::new(uri.to_string()).map_err(|e| UpstreamError::failed(format!("bad redirect URI: {e}")))
}

/// The provider's authorization URL and what to remember until it calls back.
pub async fn begin(provider: &Provider, redirect_uri: &str) -> Result<(String, Pending), UpstreamError> {
    let github = provider.kind == "github";
    let pending = Pending {
        state: random_token(32),
        verifier: random_token(32),
        nonce: (!github).then(|| random_token(32)),
    };
    let challenge = b64url(&sha256(pending.verifier.as_bytes()));
    if github {
        let mut url = url::Url::parse(&format!("{}/login/oauth/authorize", provider.issuer))
            .map_err(|e| UpstreamError::failed(format!("bad issuer: {e}")))?;
        url.query_pairs_mut()
            .append_pair("client_id", &provider.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes(provider).join(" "))
            .append_pair("state", &pending.state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        return Ok((url.to_string(), pending));
    }
    let client = CoreClient::from_provider_metadata(
        metadata(provider).await?,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect(redirect_uri)?);
    let (state, nonce) = (pending.state.clone(), pending.nonce.clone().unwrap_or_default());
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(state),
            move || Nonce::new(nonce),
        )
        .set_pkce_challenge(PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            pending.verifier.clone(),
        )));
    for scope in scopes(provider).into_iter().filter(|s| s != "openid") {
        request = request.add_scope(Scope::new(scope));
    }
    // Let people pick an account instead of silently reusing whoever is signed in upstream.
    if provider.kind == "google" {
        request = request.add_extra_param("prompt", "select_account");
    }
    let (url, _, _) = request.url();
    Ok((url.to_string(), pending))
}

/// An `error` on the callback: access_denied means the person said no.
pub fn callback_error(provider: &Provider, query: &HashMap<String, String>) -> Option<UpstreamError> {
    let error = query.get("error")?;
    let code = if error == "access_denied" {
        "upstream_cancelled"
    } else {
        "upstream_failed"
    };
    Some(UpstreamError {
        code,
        message: format!("{} returned {error}", provider.display_name),
    })
}

/// Exchanges the callback's code and says who the person is upstream.
pub async fn finish(
    provider: &Provider,
    query: &HashMap<String, String>,
    redirect_uri: &str,
    pending: &Pending,
) -> Result<UpstreamIdentity, UpstreamError> {
    if let Some(error) = callback_error(provider, query) {
        return Err(error);
    }
    let exchange =
        |cause: String| UpstreamError::failed(format!("Code exchange with {} failed: {cause}", provider.display_name));
    if query.get("state") != Some(&pending.state) {
        return Err(exchange("state mismatch".into()));
    }
    let code = query.get("code").ok_or_else(|| exchange("no code".into()))?;
    if provider.kind == "github" {
        return github_identity(provider, code, redirect_uri, &pending.verifier).await;
    }
    let meta = metadata(provider).await?;
    // RFC 9207: when the issuer says who it is on the callback, it must be the one we asked.
    if let Some(iss) = query.get("iss")
        && iss != meta.issuer().as_str()
    {
        return Err(exchange("issuer mismatch".into()));
    }
    let issuer = meta.issuer().as_str().to_string();
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect(redirect_uri)?);
    let tokens = client
        .exchange_code(AuthorizationCode::new(code.clone()))
        .map_err(|e| exchange(e.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier.clone()))
        .request_async(&*HTTP)
        .await
        .map_err(|e| exchange(e.to_string()))?;
    let id_token = tokens.id_token().ok_or_else(|| exchange("no ID token".into()))?;
    let nonce = Nonce::new(pending.nonce.clone().unwrap_or_default());
    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce)
        .map_err(|e| exchange(e.to_string()))?;
    let subject = claims.subject().to_string();
    let mut email = claims.email().map(|e| e.to_string());
    let mut email_verified = claims.email_verified();
    let mut name = claims.name().and_then(|n| n.get(None)).map(|n| n.to_string());
    // Many issuers (Handstamp included) put email only in userinfo. The subject must match.
    if email.is_none() && client.user_info_url().is_some() {
        let info: Option<CoreUserInfoClaims> = match client.user_info(
            AccessToken::new(tokens.access_token().secret().clone()),
            Some(SubjectIdentifier::new(subject.clone())),
        ) {
            Ok(request) => request.request_async(&*HTTP).await.ok(),
            Err(_) => None,
        };
        if let Some(info) = info {
            email = info.email().map(|e| e.to_string());
            email_verified = email_verified.or(info.email_verified());
            name = name.or_else(|| info.name().and_then(|n| n.get(None)).map(|n| n.to_string()));
        }
    }
    Ok(UpstreamIdentity {
        issuer,
        subject,
        login_hint: email.clone(),
        email,
        email_verified: email_verified == Some(true),
        name,
        orgs: None,
    })
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

/// The primary verified address, else any verified one.
fn chosen_email(emails: &[GitHubEmail]) -> Option<&str> {
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .or_else(|| emails.iter().find(|e| e.verified))
        .map(|e| e.email.as_str())
}

async fn github_api(provider: &Provider, token: &str, path: &str) -> Result<Value, UpstreamError> {
    let api = provider
        .api_url
        .clone()
        .unwrap_or_else(|| "https://api.github.com".into());
    let response = HTTP
        .get(format!("{api}{path}"))
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "Handstamp")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| UpstreamError::failed(format!("{} API {path} failed: {e}", provider.display_name)))?;
    if !response.status().is_success() {
        return Err(UpstreamError::failed(format!(
            "{} API {path} answered {}",
            provider.display_name,
            response.status().as_u16()
        )));
    }
    response
        .json()
        .await
        .map_err(|e| UpstreamError::failed(format!("{} API {path}: {e}", provider.display_name)))
}

/// GitHub identity = (GitHub web URL, numeric user id). The login can be renamed; the id can't.
async fn github_identity(
    provider: &Provider,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<UpstreamIdentity, UpstreamError> {
    let failed =
        |cause: String| UpstreamError::failed(format!("Code exchange with {} failed: {cause}", provider.display_name));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", verifier)
        .append_pair("client_id", &provider.client_id)
        .append_pair("client_secret", &provider.client_secret)
        .finish();
    let response = HTTP
        .post(format!("{}/login/oauth/access_token", provider.issuer))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| failed(e.to_string()))?;
    let tokens: Value = response.json().await.map_err(|e| failed(e.to_string()))?;
    if let Some(error) = tokens.get("error").and_then(Value::as_str) {
        return Err(failed(error.to_string()));
    }
    let token = tokens
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| failed("no access token".into()))?;
    let user = github_api(provider, token, "/user").await?;
    let emails: Vec<GitHubEmail> =
        serde_json::from_value(github_api(provider, token, "/user/emails").await?).unwrap_or_default();
    let orgs = if provider.github_allowed_orgs.is_empty() {
        None
    } else {
        let list = github_api(provider, token, "/user/orgs").await?;
        Some(
            list.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|o| o.get("login").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        )
    };
    let id = match &user["id"] {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => {
            return Err(UpstreamError::failed(format!(
                "{} API /user returned no id",
                provider.display_name
            )));
        }
    };
    let email = chosen_email(&emails).map(str::to_string);
    Ok(UpstreamIdentity {
        issuer: provider.issuer.clone(),
        subject: id,
        email_verified: email.is_some(),
        email,
        name: user.get("name").and_then(Value::as_str).map(str::to_string),
        login_hint: user.get("login").and_then(Value::as_str).map(str::to_string),
        orgs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn provider(kind: &str) -> Provider {
        Provider {
            id: Uuid::nil(),
            slug: kind.into(),
            kind: kind.into(),
            display_name: "Corp".into(),
            issuer: "https://github.com".into(),
            api_url: None,
            client_id: "c".into(),
            client_secret: "s".into(),
            scopes: vec![],
            allow_signup: false,
            allowed_email_domains: vec![],
            github_allowed_orgs: vec![],
            trust_email_verified: false,
            updated_at: Utc::now(),
        }
    }

    fn email(email: &str, primary: bool, verified: bool) -> GitHubEmail {
        GitHubEmail {
            email: email.into(),
            primary,
            verified,
        }
    }

    #[test]
    fn picks_the_primary_verified_email() {
        assert_eq!(
            chosen_email(&[email("a@x", false, true), email("b@x", true, true)]),
            Some("b@x")
        );
        assert_eq!(
            chosen_email(&[email("a@x", true, false), email("b@x", false, true)]),
            Some("b@x")
        );
        assert_eq!(chosen_email(&[email("a@x", true, false)]), None);
    }

    #[test]
    fn maps_callback_errors() {
        let query = |e: &str| HashMap::from([("error".to_string(), e.to_string())]);
        assert_eq!(
            callback_error(&provider("oidc"), &query("access_denied")).unwrap().code,
            "upstream_cancelled"
        );
        assert_eq!(
            callback_error(&provider("oidc"), &query("server_error")).unwrap().code,
            "upstream_failed"
        );
        assert!(callback_error(&provider("oidc"), &HashMap::new()).is_none());
    }

    #[test]
    fn github_scopes_ask_for_orgs_only_when_needed() {
        assert_eq!(scopes(&provider("github")), ["read:user", "user:email"]);
        let restricted = Provider {
            github_allowed_orgs: vec!["reciam".into()],
            ..provider("github")
        };
        assert_eq!(scopes(&restricted), ["read:user", "user:email", "read:org"]);
        assert_eq!(scopes(&provider("oidc")), ["openid", "email", "profile"]);
    }

    #[tokio::test]
    async fn github_authorize_url_carries_pkce_and_state() {
        let (url, pending) = begin(&provider("github"), "https://id.example/upstream/github/callback")
            .await
            .unwrap();
        let url = url::Url::parse(&url).unwrap();
        assert_eq!(url.path(), "/login/oauth/authorize");
        let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(q["state"], pending.state);
        assert_eq!(q["code_challenge"], b64url(&sha256(pending.verifier.as_bytes())));
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(pending.nonce.is_none());
    }
}
