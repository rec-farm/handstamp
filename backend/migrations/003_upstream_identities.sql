-- M3: upstream identity providers, linked identities, invites and recovery. See docs/PLAN.md §2, §3.

CREATE TABLE upstream_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
  kind text NOT NULL CHECK (kind IN ('github', 'google', 'oidc')),
  display_name text NOT NULL,
  -- The identity issuer: the OIDC issuer, or the GitHub web URL (https://github.com).
  issuer text NOT NULL,
  -- GitHub only: the REST API base (https://api.github.com, or <ghe>/api/v3).
  api_url text,
  client_id text NOT NULL,
  client_secret_enc bytea NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  allow_signup boolean NOT NULL DEFAULT false,
  allowed_email_domains text[] NOT NULL DEFAULT '{}',
  github_allowed_orgs text[] NOT NULL DEFAULT '{}',
  -- Pass the upstream's email_verified through? Always true for GitHub and Google.
  trust_email_verified boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  source text NOT NULL DEFAULT 'db' CHECK (source IN ('env', 'db')),
  sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- A person's account at an upstream provider. Identity is (issuer, subject), never the email.
CREATE TABLE identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider_id uuid NOT NULL REFERENCES upstream_providers (id) ON DELETE RESTRICT,
  issuer text NOT NULL,
  subject text NOT NULL,
  email citext,
  email_verified boolean NOT NULL DEFAULT false,
  login_hint text, -- e.g. the GitHub login, for display only
  linked_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  UNIQUE (issuer, subject)
);
CREATE INDEX identities_user ON identities (user_id);

ALTER TABLE users ADD COLUMN email_identity_id uuid REFERENCES identities (id) ON DELETE SET NULL;

-- Recovery links can end the user's other sessions and remove their other passkeys.
ALTER TABLE enrollment_tokens ADD COLUMN revoke_other_methods boolean NOT NULL DEFAULT false;

ALTER TABLE webauthn_challenges DROP CONSTRAINT webauthn_challenges_purpose_check;
ALTER TABLE webauthn_challenges
  ADD CONSTRAINT webauthn_challenges_purpose_check
  CHECK (purpose IN ('authenticate', 'register', 'setup', 'enroll'));
