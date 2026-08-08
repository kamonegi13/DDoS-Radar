"""P7 R11 / C3 — the intel queue's analyst half.

Import is inert. The adjudication state is a fold of `command_record`;
there is no intel table, because WP-2.7 already put the items themselves
in `signal_observation` as ordinary L1 rows (O-17).
"""
from v3.intel.adjudication import (STATE_CONFIRMED, STATE_PENDING,
                                   STATE_REJECTED, STATES, TARGET_INTEL,
                                   adjudicated, intel_state, rejected_ids)

__all__ = ["STATES", "STATE_PENDING", "STATE_CONFIRMED", "STATE_REJECTED",
           "TARGET_INTEL", "adjudicated", "intel_state", "rejected_ids"]
