//! What the provider remembers between requests.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::random_token;

/// One client's slice of an SSO session.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Per client, so one app's sid says nothing about the others.
    pub sid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// offline_access was granted: signing out doesn't revoke this client's grant.
    #[serde(default)]
    pub persists_logout: bool,
}

/// RP-initiated logout in progress: what the confirm form posts back.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutState {
    pub secret: String,
    pub client_id: Option<String>,
    pub state: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
}

/// An SSO session. `id` is the cookie value and changes on every sign-in (fixation); `uid` is
/// stable and is what the console, interactions and tokens refer to.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    #[serde(skip)]
    pub id: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_ts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    pub exp: i64,
    #[serde(default)]
    pub authorizations: BTreeMap<String, Authorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<LogoutState>,
    /// Not persisted: whether this request created or changed it.
    #[serde(skip)]
    pub new: bool,
    #[serde(skip)]
    pub touched: bool,
}

impl Session {
    pub fn fresh(ttl: i64) -> Self {
        Self {
            id: random_token(32),
            uid: random_token(16),
            account_id: None,
            login_ts: None,
            amr: None,
            exp: super::store::now() + ttl,
            authorizations: BTreeMap::new(),
            state: None,
            new: true,
            touched: false,
        }
    }

    pub fn authorization(&mut self, client_id: &str) -> &mut Authorization {
        self.touched = true;
        self.authorizations
            .entry(client_id.to_string())
            .or_insert_with(|| Authorization { sid: random_token(16), ..Default::default() })
    }

    pub fn grant_id_for(&self, client_id: &str) -> Option<&str> {
        self.authorizations.get(client_id).and_then(|a| a.grant_id.as_deref())
    }

    /// Seconds since sign-in exceed max_age.
    pub fn past(&self, max_age: i64) -> bool {
        self.login_ts.is_none_or(|ts| super::store::now() - ts > max_age)
    }

    /// A new cookie value, so a session ID seen before sign-in can't be ridden after it.
    pub fn reset_identifier(&mut self) {
        self.id = random_token(32);
        self.touched = true;
    }
}

/// The outcome of an interaction, as the sign-in card reports it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InteractionResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResult {
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    pub ts: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prompt {
    pub name: String,
    pub reasons: Vec<String>,
    pub details: Map<String, Value>,
}

/// An authorization request waiting for the person: sign in, pass the access check, consent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interaction {
    pub uid: String,
    pub params: BTreeMap<String, String>,
    pub prompt: Prompt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_submission: Option<InteractionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<InteractionResult>,
    pub exp: i64,
}

impl Interaction {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    pub fn client_id(&self) -> &str {
        self.param("client_id").unwrap_or_default()
    }
}

/// What a person allowed a client: OIDC scopes and individually requested claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub jti: String,
    pub account_id: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
    #[serde(default)]
    pub claims: BTreeSet<String>,
    pub exp: i64,
}

impl Grant {
    pub fn new(account_id: &str, client_id: &str, ttl: i64) -> Self {
        Self {
            jti: random_token(16),
            account_id: account_id.into(),
            client_id: client_id.into(),
            scopes: BTreeSet::new(),
            claims: BTreeSet::new(),
            exp: super::store::now() + ttl,
        }
    }

    pub fn add_scopes<'a>(&mut self, scopes: impl IntoIterator<Item = &'a str>) {
        self.scopes.extend(scopes.into_iter().map(str::to_string));
    }

    pub fn add_claims<'a>(&mut self, claims: impl IntoIterator<Item = &'a str>) {
        self.claims.extend(claims.into_iter().map(str::to_string));
    }

    /// The requested scopes this grant covers, in request order.
    pub fn filter_scopes<'a>(&self, requested: &[&'a str]) -> Vec<&'a str> {
        requested.iter().copied().filter(|s| self.scopes.contains(*s)).collect()
    }
}

/// Everything the token endpoint needs from the authorization request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Code {
    pub client_id: String,
    pub account_id: String,
    pub grant_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub redirect_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    pub auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub session_uid: String,
    pub expires_with_session: bool,
}

/// Opaque access token for userinfo and introspection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessToken {
    pub client_id: String,
    pub account_id: String,
    pub grant_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    pub session_uid: String,
    pub expires_with_session: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

/// Refresh token. Rotated on every use; a replay revokes the whole grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshToken {
    pub client_id: String,
    pub account_id: String,
    pub grant_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub session_uid: String,
    pub expires_with_session: bool,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub rotations: u32,
}
