"""Migration ETL — v1 SQLite into the v3 ledger (WP-2.3).

Reads the source through a read-only connection and writes exclusively
through LedgerStore, so v1's stringly-typed rows meet the kernel's
validation at the boundary rather than after they are already stored.

    migrate()     copy the migratable tables, quarantining what will not fit
    reconcile()   S3's five acceptance criteria, as a machine-readable report
"""
from v3.etl.mapping import MIGRATABLE, NOT_YET_MIGRATABLE
from v3.etl.migrate import DEFAULT_CHUNK_SIZE, ETLReport, migrate
from v3.etl.reconcile import ReconciliationReport, reconcile
from v3.etl.source import V1Source

__all__ = ["migrate", "ETLReport", "reconcile", "ReconciliationReport",
           "V1Source", "MIGRATABLE", "NOT_YET_MIGRATABLE",
           "DEFAULT_CHUNK_SIZE"]
