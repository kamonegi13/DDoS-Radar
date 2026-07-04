#!/bin/sh
# Backup the live radar.db from the ddos-radar container's named volume.
#
# The production DB lives in the docker named volume `ddos-radar_radar-data`
# (mounted at /app/radar/persistence), NOT in the repo working tree. This
# script takes a consistent snapshot via the SQLite online backup API (safe
# against concurrent WAL writers), copies it to the host, compresses it, and
# rotates old backups.
#
# Usage:  scripts/backup_radar_db.sh [dest_dir]
# Cron:   0 4 * * *  /Users/juzo1192/git/DDoS-Radar/scripts/backup_radar_db.sh
set -eu

CONTAINER="ddos-radar"
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

# Rotate: keep newest $KEEP backups.
ls -1t "${DEST_DIR}"/radar-*.db.gz 2>/dev/null | tail -n "+$((KEEP + 1))" | while IFS= read -r old; do
    rm -f "${old}"
    echo "rotated out: ${old}"
done
