#!/bin/sh
# Canonical way to take an ops-health measurement from the live container.
#
# Usage:  scripts/run_ops_health.sh [container_name]   (default: noroshi)
#
# Prints JSON: database / WAL sizes, row counts for the curated trend
# tables, signal-ledger age, and the backup marker state.
#
# WHY A WRAPPER, AND WHY BY FILE PATH
#
# The obvious-looking invocation is wrong and cannot be made safe from
# inside the module:
#
#     docker exec noroshi python3 -m radar.verification.ops_health   # NO
#
# `-m` imports the parent packages first, so radar/__init__.py executes
# and boots a SECOND copy of the whole application — database migrations
# and ~30 sensor threads with live outbound HTTP — inside the container
# that is already running one. That happens before any line of
# ops_health.py runs, so no guard in that file can prevent it.
#
# Running the file by path keeps it out of the package import machinery
# entirely: radar/__init__.py is never imported, and the module's
# stdlib-only top level means nothing else starts either.
#
# Do not pipe the source into `python3 -` either: without a real file on
# disk the persistence path cannot be resolved and every size reads 0,
# which is indistinguishable from an empty database. The script refuses
# to run that way on purpose.
#
# Follow-up (not this script's problem): the root cause is that
# radar/__init__.py has import-time side effects at all. Making imports
# side-effect-free is v3 L0/L6 work.
set -eu

CONTAINER="${1:-noroshi}"

exec docker exec "${CONTAINER}" \
    python3 /app/radar/verification/ops_health.py
