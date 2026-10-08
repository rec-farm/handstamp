-- M2: passkeys and first-run setup. See docs/PLAN.md §2.

-- WebAuthn user handle: random, never the `sub` (WebAuthn §14.6.1). Set when the first passkey is made.
ALTER TABLE users ADD COLUMN webauthn_user_handle text UNIQUE;

CREATE TABLE passkeys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE, -- base64url
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0,
  transports text[] NOT NULL DEFAULT '{}',
  aaguid uuid,
  device_type text NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up boolean NOT NULL DEFAULT false,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX passkeys_user ON passkeys (user_id);

-- Single-use, short-lived. `binding` ties a challenge to the interaction uid or console session
-- that asked for it, so a challenge can't be replayed elsewhere.
CREATE TABLE webauthn_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge text NOT NULL UNIQUE,
  purpose text NOT NULL CHECK (purpose IN ('authenticate', 'register', 'setup')),
  binding text NOT NULL,
  user_id uuid REFERENCES users (id) ON DELETE CASCADE,
  pending jsonb NOT NULL DEFAULT '{}', -- e.g. the display name chosen during setup
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX webauthn_challenges_binding ON webauthn_challenges (binding);
CREATE INDEX webauthn_challenges_expires ON webauthn_challenges (expires_at);

-- Setup tokens now; invites and recovery links in M3.
CREATE TABLE enrollment_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash bytea NOT NULL UNIQUE, -- sha256
  purpose text NOT NULL CHECK (purpose IN ('setup', 'invite', 'recovery')),
  user_id uuid REFERENCES users (id) ON DELETE CASCADE,
  bound_to text, -- the interaction uid that proved the token
  created_by uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_user_id uuid REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX enrollment_tokens_purpose ON enrollment_tokens (purpose, expires_at);

