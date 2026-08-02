#!/bin/sh
# Post-deploy driver for the 2026-08-02 cross-scenario attribution remediation.
#
# Prerequisite (run manually first — rebuilds the image with the fixed
# attribution gate / tier split and restarts the container):
#
#     docker compose build && docker compose up -d
#
# Then:
#
#     scripts/apply_attribution_remediation.sh
#
# Steps: surgically purge cross-scenario auto:rss labels + reset the korea
# loosening chain, re-run both ground-truth ETLs with the fixed attribution,
# snapshot a fresh recall baseline, and copy it back into the repo for commit.
set -eu

CONTAINER="ddos-radar"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== waiting for ${CONTAINER} to be healthy =="
for _ in $(seq 1 30); do
    status="$(docker inspect -f '{{.State.Health.Status}}' "${CONTAINER}" 2>/dev/null || echo missing)"
    [ "${status}" = "healthy" ] && break
    sleep 5
done
docker inspect -f 'container health: {{.State.Health.Status}}' "${CONTAINER}"

echo "== [1/4] purge cross-scenario labels + reset thresholds =="
docker exec "${CONTAINER}" python3 scripts/remediate_cross_scenario_labels.py --apply

echo "== [2/4] re-run RSS ground-truth ETL (conflict-party attribution) =="
docker exec "${CONTAINER}" python3 scripts/run_rss_etl.py --limit 20000

echo "== [3/4] re-run ACLED/GDELT ground-truth ETL =="
docker exec "${CONTAINER}" python3 scripts/run_ground_truth_etl.py --limit 20000

echo "== [4/4] snapshot fresh recall baseline =="
docker exec "${CONTAINER}" python3 scripts/check_recall_baseline.py --update
docker cp "${CONTAINER}:/app/docs/baselines/recall_metrics.json" \
    "${REPO_ROOT}/docs/baselines/recall_metrics.json"

echo
echo "done. Next: review 'git diff docs/baselines/recall_metrics.json' and commit it."
