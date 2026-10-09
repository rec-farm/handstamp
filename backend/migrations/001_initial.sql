-- M1: protocol skeleton. See docs/PLAN.md §2.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), -- this is `sub`
  display_name text NOT NULL,
  preferred_username citext UNIQUE,
  email citext,
  email_verified boolean NOT NULL DEFAULT false,
  is_admin boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_sign_in_at timestamptz
);
-- Two users can never both present the same verified email to a relying party.
CREATE UNIQUE INDEX users_verified_email_key ON users (email) WHERE email_verified;

CREATE TABLE oidc_clients (
  client_id text PRIMARY KEY,
  source text NOT NULL DEFAULT 'db' CHECK (source IN ('db', 'file', 'builtin')),
  name text NOT NULL,
  client_secret_enc bytea, -- NULL means a public client
  token_endpoint_auth_method text NOT NULL,
  redirect_uris text[] NOT NULL,
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  allowed_scopes text[] NOT NULL,
  first_party boolean NOT NULL DEFAULT false,
  require_pkce boolean NOT NULL DEFAULT true,
  backchannel_logout_uri text,
  enabled boolean NOT NULL DEFAULT true,
  secret_rotated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((token_endpoint_auth_method = 'none') = (client_secret_enc IS NULL))
);

CREATE TABLE signing_keys (
  kid text PRIMARY KEY,
  alg text NOT NULL,
  private_jwk_enc bytea, -- wiped when retired
  public_jwk jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('staged', 'active', 'retiring', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  retire_after timestamptz,
  retired_at timestamptz
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (alg) WHERE state = 'active';

CREATE TABLE cookie_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key_enc bytea NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX cookie_keys_one_active ON cookie_keys ((true)) WHERE state = 'active';

-- Storage for oidc-provider models (Session, Interaction, AuthorizationCode, AccessToken,
-- RefreshToken, Grant, ...). Clients are not stored here; see oidc_clients.
CREATE TABLE oidc_payloads (
  kind text NOT NULL,
  id text NOT NULL,
  payload jsonb NOT NULL,
  grant_id text,
  uid text,
  user_code text,
  account_id text,
  expires_at timestamptz,
  consumed_at timestamptz,
  PRIMARY KEY (kind, id)
);
CREATE INDEX oidc_payloads_grant_id ON oidc_payloads (grant_id) WHERE grant_id IS NOT NULL;
CREATE INDEX oidc_payloads_uid ON oidc_payloads (kind, uid) WHERE uid IS NOT NULL;
CREATE INDEX oidc_payloads_user_code ON oidc_payloads (kind, user_code) WHERE user_code IS NOT NULL;
CREATE INDEX oidc_payloads_account ON oidc_payloads (kind, account_id) WHERE account_id IS NOT NULL;
CREATE INDEX oidc_payloads_expires_at ON oidc_payloads (expires_at);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'cli')),
  actor_user_id uuid,
  action text NOT NULL,
  target_type text,
  target_id text,
  client_id text,
  ip_prefix inet,
  user_agent text,
  metadata jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at DESC);
CREATE INDEX audit_log_actor ON audit_log (actor_user_id, at DESC);
CREATE INDEX audit_log_target ON audit_log (target_type, target_id, at DESC);
CREATE INDEX audit_log_action ON audit_log (action, at DESC);

CREATE TABLE instance_settings (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  instance_name text NOT NULL DEFAULT 'Handstamp',
  setup_completed_at timestamptz,
  require_two_methods boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO instance_settings (id) VALUES (1);
