#!/bin/sh
# Backup the live radar.db from the noroshi container's named volume.
#
# The production DB lives in the docker named volume `noroshi_radar-data`
# (mounted at /app/radar/persistence), NOT in the repo working tree. This
# script takes a consistent snapshot via the SQLite online backup API (safe
# against concurrent WAL writers), copies it to the host, compresses it, and
# rotates old backups.
#
# Usage:  scripts/backup_radar_db.sh [dest_dir]
# Cron:   0 4 * * *  /Users/juzo1192/git/Noroshi/scripts/backup_radar_db.sh
set -eu

# cron runs with a minimal PATH that omits the docker CLI, which made every
# scheduled run fail with "docker: command not found" (silently, since only the
# log recorded it). Prepend the usual homebrew / local install dirs.
PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"
export PATH

CONTAINER="noroshi"
DEST_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)/backups}"
KEEP=14
STAMP="$(date +%Y%m%d-%H%M%S)"
TMP_IN_CONTAINER="/tmp/radar-backup-${STAMP}.db"
OUT="${DEST_DIR}/radar-${STAMP}.db"

mkdir -p "${DEST_DIR}"

# Consistent snapshot via sqlite3 online backup API (container has no sqlite3
# CLI, so use python3). Read-only source connection; WAL-safe.
docker exec -i "${CONTAINER}" python3 - "${TMP_IN_CONTAINER}" <<'EOF'
import sqlite3
import sys

dest_path = sys.argv[1]
src = sqlite3.connect("file:/app/radar/persistence/radar.db?mode=ro", uri=True)
dst = sqlite3.connect(dest_path)
with dst:
    src.backup(dst)
src.close()
dst.close()
print(f"snapshot written: {dest_path}")
EOF

docker cp "${CONTAINER}:${TMP_IN_CONTAINER}" "${OUT}"
docker exec "${CONTAINER}" rm -f "${TMP_IN_CONTAINER}"

gzip -f "${OUT}"
echo "backup: ${OUT}.gz ($(du -h "${OUT}.gz" | cut -f1))"

# Record completion where the APPLICATION can see it. Backups land here on
# the host, but the container's database lives in the noroshi_radar-data
# volume — the app cannot see this directory at all, so without a marker
# "when did we last back up?" is unanswerable from inside. That is exactly
# how the 2026-07-04..08-03 outage stayed invisible for a month
# (S4-NF-053). radar/verification/ops_health.py reads this file's age.
BACKUP_SIZE="$(wc -c < "${OUT}.gz" | tr -d ' ')"
if ! docker exec -i "${CONTAINER}" python3 - \
        "$(basename "${OUT}.gz")" "${BACKUP_SIZE}" <<'EOF'
import json
import os
import sys
import time

marker = "/app/radar/persistence/backup_state.json"
payload = {
    "last_backup_at": time.time(),
    "backup_file": sys.argv[1],
    "size_bytes": int(sys.argv[2]),
}
tmp = f"{marker}.tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
os.replace(tmp, marker)   # atomic: never leave a half-written marker
print(f"backup marker updated: {marker}")
EOF
then
    # Non-fatal: the backup itself succeeded. But say so loudly — a stale
    # marker makes ops_health report the backup as overdue, which is the
    # correct failure direction (a missing signal must not read as OK).
    echo "WARNING: backup succeeded but the marker could not be written;" \
         "ops_health will report the backup as overdue" >&2
fi

# Rotate: keep newest $KEEP backups.
ls -1t "${DEST_DIR}"/radar-*.db.gz 2>/dev/null | tail -n "+$((KEEP + 1))" | while IFS= read -r old; do
    rm -f "${old}"
    echo "rotated out: ${old}"
done
