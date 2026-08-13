"""V3-SEC-01 remediation, part 3 of 3: discard the shadow's command ledger.

P3's cutover-blocker table prescribes three parts: (1) no plaintext at
write time (landed 2026-08-13, commit 1b2da77), (2) the sweep reads the
stored bytes (same commit), (3) **the existing ledger rows are discarded
and the bootstrap password rotated** — because the ledger is append-only
(triggers refuse UPDATE and DELETE) and the rows that already hold the
plaintext cannot be edited, only dropped with their table.

DROP TABLE bypasses the row-level triggers by design: the append-only
property protects HISTORY from silent revision, not a leaked secret from
remediation. The schema layer recreates the table empty on next boot, and
the composition root's bootstrap then registers the first administrator
from the ROTATED password — hashed at the producer now, never plaintext.

Run from a one-off container on the shadow volume, with the app STOPPED:

    docker compose --profile shadow stop v3_shadow
    docker compose --profile shadow run --rm --no-deps \
        --entrypoint python3 v3_shadow /app/scripts/v3_discard_command_ledger.py
    docker compose --profile shadow up -d v3_shadow

Deliberately narrow: this drops command_record and NOTHING else. The
observation ledger (signal_observation, tl_observation, baselines …) is
untouched — it holds no credentials and weeks of shadow history.

The empty table is recreated HERE, not left to boot: command_record
belongs to migration 5, `schema_meta` already records a version past it,
and `_migrate` never re-runs an applied step — measured 2026-08-13, when
the first run of this script left the worker unable to boot ("no such
table: command_record"). The migration's statements are all
IF-NOT-EXISTS, so replaying exactly the ones that mention this table is
idempotent and keeps the DDL single-sourced.
"""
import sqlite3
import sys

LEDGER = "/app/v3data/noroshi_v3.db"


def _rebuild_statements() -> tuple[str, ...]:
    from v3.ledger.migrations import MIGRATIONS
    return tuple(statement for migration in MIGRATIONS
                 for statement in migration.statements
                 if "command_record" in statement)


def main() -> int:
    con = sqlite3.connect(LEDGER)
    try:
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        discarded = 0
        if "command_record" in tables:
            discarded = con.execute(
                "SELECT COUNT(*) FROM command_record").fetchone()[0]
            con.execute("DROP TABLE command_record")
        statements = _rebuild_statements()
        for statement in statements:
            con.execute(statement)
        con.commit()
        con.execute("VACUUM")  # the plaintext bytes leave the file, not
        con.close()            # just the table's b-tree
        print(f"command_record discarded ({discarded} row(s), including "
              f"the plaintext user.register payload — V3-SEC-01) and "
              f"recreated empty via {len(statements)} migration "
              f"statement(s); file vacuumed")
        return 0
    except sqlite3.Error as failure:
        print(f"discard FAILED: {failure}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
