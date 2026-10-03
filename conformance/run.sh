#!/usr/bin/env bash
# Runs the OpenID conformance suite (pinned) against a local Handstamp. See docs/PLAN.md §5.2.
#
#   ./conformance/run.sh            Config OP + Basic OP smoke subset (the M1 gate)
#   ./conformance/run.sh full       Config OP + full Basic OP
#   ./conformance/run.sh down       Stop and remove the stack
#
# Needs Docker and uv. Results land in conformance/results/.
set -euo pipefail
cd "$(dirname "$0")"

SUITE_REF=release-v5.3.1
BASIC='oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]'
SMOKE='oidcc-server,oidcc-userinfo-get,oidcc-refresh-token,oidcc-ensure-redirect-uri-in-authorization-request,oidcc-prompt-login,oidcc-max-age-1,oidcc-id-token-hint,oidcc-scope-email'

if [[ "${1:-}" == down ]]; then
  docker compose down --volumes
  exit 0
fi

# certs-keys holds placeholder material for other suites; our plans need none.
mkdir -p results/scripts/certs-keys results/export
for script in run-test-plan.py conformance.py test_plan_parser.py; do
  [[ -f results/scripts/$script ]] ||
    curl -fsSL "https://gitlab.com/openid/conformance-suite/-/raw/$SUITE_REF/scripts/$script" -o "results/scripts/$script"
done

docker compose up --detach --build --wait db handstamp caddy mongodb server nginx

echo "Waiting for the suite and Handstamp…"
ready=0
for _ in $(seq 1 90); do
  if curl -skf https://localhost.emobix.co.uk:8443/api/runner/available >/dev/null &&
    docker compose exec -T server sh -c 'wget -q --no-check-certificate -O /dev/null https://handstamp.test/.well-known/openid-configuration || curl -skf https://handstamp.test/.well-known/openid-configuration >/dev/null'; then
    ready=1
    break
  fi
  sleep 2
done
if [[ $ready != 1 ]]; then
  echo "The suite or Handstamp did not come up. Check: docker compose -f conformance/compose.yaml logs" >&2
  exit 1
fi

# The runner fails when an expected warning or skip does not happen, so the expected-results
# files (known, accepted gaps) only apply to the full plans.
EXPECTED=()
if [[ "${1:-}" == full ]]; then
  PLANS=(oidcc-config-certification-test-plan handstamp-oidcc.json "$BASIC" handstamp-oidcc.json)
  EXPECTED=(--expected-failures-file expected-failures.json --expected-skips-file expected-skips.json)
else
  PLANS=(oidcc-config-certification-test-plan handstamp-oidcc.json "$BASIC:$SMOKE" handstamp-oidcc.json)
fi

export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/
export CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/
export CONFORMANCE_DEV_MODE=1
uv run --quiet --with httpx --with pyparsing python results/scripts/run-test-plan.py \
  --export-dir results/export --verbose ${EXPECTED[@]+"${EXPECTED[@]}"} "${PLANS[@]}"
