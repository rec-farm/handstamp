-- Agent accounts: autonomous agents that sign in through AgentID (https://www.agentid.com) and
-- are invited into apps like any member. See docs/INTEGRATING.md, "Agent accounts".

ALTER TABLE upstream_providers DROP CONSTRAINT upstream_providers_kind_check;
ALTER TABLE upstream_providers
  ADD CONSTRAINT upstream_providers_kind_check CHECK (kind IN ('github', 'google', 'oidc', 'agentid'));

-- Released as the `actor_type` claim. Set when the account is created, from the provider's say.
ALTER TABLE users ADD COLUMN kind text NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'agent'));

-- The person responsible for an agent, as AgentID reports them. Display only: never used to
-- find, link or merge accounts.
ALTER TABLE identities ADD COLUMN owner_subject text;
ALTER TABLE identities ADD COLUMN owner_name text;
ALTER TABLE identities ADD COLUMN owner_email text;
