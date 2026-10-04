# config

`compose.yaml` mounts this directory read-only at `/config` in the Handstamp container
(`HANDSTAMP_CONFIG_DIR` points it elsewhere). Put a clients file here and set
`HANDSTAMP_CLIENTS_FILE=/config/clients.json` to declare apps as code; see
[`examples/clients.json`](../examples/clients.json) and
[Deploying → Clients as code](../docs/DEPLOYING.md#operations-notes).

Files you add here are ignored by git.
