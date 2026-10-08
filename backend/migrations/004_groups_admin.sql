-- M4: groups (the `groups` claim) and per-app access. See docs/PLAN.md §2, R7.

CREATE TABLE groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- The value apps see in the `groups` claim.
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  added_by uuid REFERENCES users (id) ON DELETE SET NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members (user_id);

-- Only members of this group may sign in to the app (R7).
ALTER TABLE oidc_clients ADD COLUMN required_group_id uuid REFERENCES groups (id) ON DELETE SET NULL;
