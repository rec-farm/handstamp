//! The audit log (S19). Metadata holds allowlisted, non-secret facts only: IDs, counts, reasons.

use anyhow::Result;
use serde_json::{Value, json};
use deadpool_postgres::GenericClient;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    User,
    Admin,
    System,
    Cli,
}

impl Actor {
    pub fn as_str(self) -> &'static str {
        match self {
            Actor::User => "user",
            Actor::Admin => "admin",
            Actor::System => "system",
            Actor::Cli => "cli",
        }
    }
}

pub struct Entry<'a> {
    pub action: &'a str,
    pub actor: Actor,
    pub actor_user_id: Option<Uuid>,
    pub target_type: Option<&'a str>,
    pub target_id: Option<String>,
    pub client_id: Option<&'a str>,
    pub ip_prefix: Option<String>,
    pub user_agent: Option<&'a str>,
    pub metadata: Value,
}

impl<'a> Entry<'a> {
    pub fn new(action: &'a str, actor: Actor) -> Self {
        Self {
            action,
            actor,
            actor_user_id: None,
            target_type: None,
            target_id: None,
            client_id: None,
            ip_prefix: None,
            user_agent: None,
            metadata: json!({}),
        }
    }

    pub fn by(mut self, user: Option<Uuid>) -> Self {
        self.actor_user_id = user;
        self
    }

    pub fn target(mut self, kind: &'a str, id: impl ToString) -> Self {
        self.target_type = Some(kind);
        self.target_id = Some(id.to_string());
        self
    }

    pub fn client(mut self, client_id: &'a str) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn from(mut self, ip_prefix: Option<String>, user_agent: Option<&'a str>) -> Self {
        self.ip_prefix = ip_prefix;
        self.user_agent = user_agent;
        self
    }

    pub fn meta(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub async fn write(self, db: &impl GenericClient) -> Result<()> {
        let user_agent: Option<String> = self.user_agent.map(|ua| ua.chars().take(256).collect());
        db.execute(
            "INSERT INTO audit_log (action, actor_type, actor_user_id, target_type, target_id, client_id, ip_prefix, user_agent, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::inet, $8, $9)",
            &[
                &self.action,
                &self.actor.as_str(),
                &self.actor_user_id,
                &self.target_type,
                &self.target_id,
                &self.client_id,
                &self.ip_prefix,
                &user_agent,
                &self.metadata,
            ],
        )
        .await?;
        Ok(())
    }
}

/// A network prefix, not the full address: enough to spot patterns, less personal data.
pub fn ip_prefix(ip: Option<std::net::IpAddr>) -> Option<String> {
    use std::net::IpAddr;
    let ip = ip?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            Some(format!("{a}.{b}.{c}.0/24"))
        }
        IpAddr::V6(v6) if v6.is_loopback() => Some("::1/128".into()),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ip_prefix;

    #[test]
    fn keeps_a_prefix_only() {
        assert_eq!(ip_prefix(Some("203.0.113.77".parse().unwrap())).unwrap(), "203.0.113.0/24");
        assert_eq!(ip_prefix(Some("::ffff:10.1.2.3".parse().unwrap())).unwrap(), "10.1.2.0/24");
        assert_eq!(ip_prefix(Some("::1".parse().unwrap())).unwrap(), "::1/128");
        assert_eq!(ip_prefix(Some("2001:db8:1:2::5".parse().unwrap())).unwrap(), "2001:db8:1::/48");
        assert_eq!(ip_prefix(None), None);
    }
}
