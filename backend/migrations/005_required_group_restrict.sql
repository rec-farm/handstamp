-- An app's required group must not disappear from under it: deleting the group would otherwise set
-- required_group_id to NULL and silently open the app to everyone. Fail closed instead (R7).
ALTER TABLE oidc_clients DROP CONSTRAINT IF EXISTS oidc_clients_required_group_id_fkey;
ALTER TABLE oidc_clients
  ADD CONSTRAINT oidc_clients_required_group_id_fkey
  FOREIGN KEY (required_group_id) REFERENCES groups (id) ON DELETE RESTRICT;
