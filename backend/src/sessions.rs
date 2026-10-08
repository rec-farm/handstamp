//! SSO sessions read and ended from outside a protocol request: sign out everywhere, revoking one
//! device, disabling a user.

use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

use crate::{
    app::App,
    db::iso,
    oidc::{logout::backchannel, models::Session, store::SESSION},
};

impl App {
    async fn sessions_of(&self, account_id: &str, uid: Option<&str>) -> Result<Vec<Session>> {
        let db = self.pool.get().await?;
        let rows = db
            .query(
                "SELECT payload FROM oidc_payloads WHERE kind = $1 AND account_id = $2 \
                 AND ($3::text IS NULL OR uid = $3) AND (expires_at IS NULL OR expires_at > now())",
                &[&SESSION, &account_id, &uid],
            )
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| serde_json::from_value(r.get(0)).ok())
            .collect())
    }

    pub async fn session_exists(&self, account_id: &str, uid: &str) -> Result<bool> {
        Ok(!self.sessions_of(account_id, Some(uid)).await?.is_empty())
    }

    /// The SSO session a client's `sid` belongs to (sid is per client inside the session).
    pub async fn session_uid_for_sid(&self, account_id: &str, client_id: &str, sid: &str) -> Result<Option<String>> {
        Ok(self
            .sessions_of(account_id, None)
            .await?
            .into_iter()
            .find(|s| s.authorizations.get(client_id).is_some_and(|a| a.sid == sid))
            .map(|s| s.uid))
    }

    pub async fn list_sessions(&self, account_id: &str) -> Result<Vec<Value>> {
        let mut sessions = self.sessions_of(account_id, None).await?;
        let client_ids: BTreeSet<String> = sessions.iter().flat_map(|s| s.authorizations.keys().cloned()).collect();
        let names: HashMap<String, String> = if client_ids.is_empty() {
            HashMap::new()
        } else {
            let ids: Vec<String> = client_ids.into_iter().collect();
            let db = self.pool.get().await?;
            db.query(
                "SELECT client_id, name FROM oidc_clients WHERE client_id = ANY($1)",
                &[&ids],
            )
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect()
        };
        sessions.sort_by(|a, b| b.login_ts.cmp(&a.login_ts));
        Ok(sessions
            .iter()
            .map(|s| {
                let amr = s.amr.clone().unwrap_or_default();
                json!({
                    "uid": s.uid,
                    "signedInAt": s.login_ts.and_then(|t| Utc.timestamp_opt(t, 0).single()).map(iso),
                    "expiresAt": Utc.timestamp_opt(s.exp, 0).single().map(iso),
                    "method": if amr.iter().any(|m| m == "pop") { "passkey".to_string() } else if amr.is_empty() { "other".to_string() } else { amr.join(" ") },
                    "apps": s.authorizations.keys().map(|id| json!({ "clientId": id, "name": names.get(id).cloned().unwrap_or_else(|| id.clone()) })).collect::<Vec<_>>(),
                })
            })
            .collect())
    }

    /// Ends sessions: every app in them gets a back-channel logout, and the grants (with their
    /// tokens) are revoked. Without `uid` ("sign out everywhere"), grants that outlive sessions
    /// (offline_access) go too.
    pub async fn end_sessions(&self, account_id: &str, uid: Option<&str>) -> Result<usize> {
        let sessions = self.sessions_of(account_id, uid).await?;
        let mut grants: Vec<String> = Vec::new();
        for session in &sessions {
            for (client_id, authorization) in &session.authorizations {
                if let Some(grant) = &authorization.grant_id {
                    grants.push(grant.clone());
                }
                backchannel(
                    self,
                    client_id.clone(),
                    account_id.to_string(),
                    authorization.sid.clone(),
                );
            }
        }
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        if uid.is_none() {
            let rows = tx
                .query(
                    "SELECT id FROM oidc_payloads WHERE kind = 'grant' AND account_id = $1",
                    &[&account_id],
                )
                .await?;
            grants.extend(rows.iter().map(|r| r.get::<_, String>(0)));
        }
        if !grants.is_empty() {
            tx.execute("DELETE FROM oidc_payloads WHERE grant_id = ANY($1)", &[&grants])
                .await?;
        }
        tx.execute(
            "DELETE FROM oidc_payloads WHERE kind = $1 AND account_id = $2 AND ($3::text IS NULL OR uid = $3)",
            &[&SESSION, &account_id, &uid],
        )
        .await?;
        tx.commit().await?;
        Ok(sessions.len())
    }

    pub async fn live_session_count(&self) -> Result<i64> {
        let db = self.pool.get().await?;
        Ok(db
            .query_one(
                "SELECT count(*) FROM oidc_payloads WHERE kind = $1 AND (expires_at IS NULL OR expires_at > now())",
                &[&SESSION],
            )
            .await?
            .get(0))
    }
}
