-- Rate-limit windows in Postgres, so every replica counts against one budget (R5). Unlogged:
-- a crash only resets the counts. One row per (limit, route, client IP).
CREATE UNLOGGED TABLE rate_limits (
  key text PRIMARY KEY,
  started timestamptz NOT NULL,
  hits integer NOT NULL
);
CREATE INDEX rate_limits_started ON rate_limits (started);
