"""radar.verification -- L5 self-verification layer (v3 Phase 1).

Built against the *current* system on purpose: the seven silent detection
failures found in the 2026-08 design audit all worked correctly when they
were written. A monitor that cannot detect the failures that already
happened cannot be trusted to detect the next ones, so L5 is verified
against known defects (WP-1.1 acceptance target: F-08 / gps_jamming)
before it is carried into v3.

Modules:
    flag_catalog    declarative catalog of every sensor detection flag,
                    plus the pure evaluator (S5-VERIF-001)
    firing_monitor  persistence, silence verdicts, and the daily job
                    (S5-VERIF-002 / 003 / 004 / 016)
"""
