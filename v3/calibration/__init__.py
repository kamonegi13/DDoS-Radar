"""L4 — the calibration layer.

This is the layer that broke three times (2026-05-29 blanket-TP,
2026-07-03 TL inversion, 2026-08-02 cross-scenario attribution), and each
time it broke it kept passing its tests while degrading production for
weeks. D2 D-01 records the conclusion: a bug in the label generator is not
fixed by structure. So the structure here is aimed at a narrower, more
achievable target — making the SHAPES that hid those three bugs
unrepresentable:

    epoch      a label carries the generator and epoch that produced it;
               two measurements from different epochs cannot be handed to
               a comparison, because the comparison takes a proof of
               alignment rather than two loose snapshots (F-16).
    matrix     a confusion cell whose recall is 1.0 by construction
               (fn == 0 and tn == 0) cannot be built into evidence, so it
               cannot back a proposal or a gate verdict (incident #1).
    recall     one implementation of the arithmetic, with `None` (not
               0.0) for an undefined denominator (S5-VERIF-035).
    authority  a calibration write needs an authorisation token that only
               `authorize()` mints, and an automated actor's identity is
               structurally distinct from an analyst's (G-01).
    guards     one evaluator for generation, application and rejection;
               the permit it returns cannot be constructed anywhere else,
               so the tested path and the running path are the same path
               (E-03).
    labels     the one door a label enters through, and the only module
               that may build a `LabelRecord` — proved by AST, because
               the epoch coherence check lives here and L1 can only
               enforce presence (WP-3.3).
    lifecycle  the proposal's six states, held as the fold of its
               adjudication commands rather than as a column an UPDATE
               moves (S1-CALIB-052 / ACCIDENTAL A9).
    queue      emission behind the generation Permit, and R13's
               projection: the emitted row, its folded state, and the
               trail that moved it.

Import-inert, no environment reads, no HTTP: the v3 invariants.
"""
from __future__ import annotations

__all__ = ["epoch", "matrix", "recall", "authority", "guards",
           "labels", "lifecycle", "queue"]
