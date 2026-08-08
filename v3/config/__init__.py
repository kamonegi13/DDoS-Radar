"""v3's own configuration layer: which keys may move, and what answered.

Two modules, and the split is the ruling (WP-4.1d):

    registry    WHICH keys are operationally variable (P6 O-18 group (a)),
                what each defaults to, why it is variable, and — the part
                WP-1.2 proved matters — WHO reads it. Pure data.
    resolution  HOW a key resolves: override -> env -> default, with the
                layer that answered carried out alongside the value.

Neither module reads the environment. The composition root does that
(`v3/runtime/secrets.py`, the one licensed reader) and hands the snapshot
to `ConfigResolver`, so a resolver is a value a test can build and an
import can never accidentally configure.
"""
from v3.config.registry import (RegisteredKey, VARIABLE_KEYS, coerce_value,
                                default_of, entry_for, is_variable,
                                pinned_disclosure, refuse_if_not_variable,
                                variable_disclosure, variable_keys)
from v3.config.resolution import (ConfigResolver, ConfigValue, LAYERS,
                                  SOURCE_DEFAULT, SOURCE_ENV, SOURCE_OVERRIDE)

__all__ = ["RegisteredKey", "VARIABLE_KEYS", "coerce_value", "default_of",
           "entry_for", "is_variable", "pinned_disclosure",
           "refuse_if_not_variable", "variable_disclosure", "variable_keys",
           "ConfigResolver", "ConfigValue", "LAYERS", "SOURCE_DEFAULT",
           "SOURCE_ENV", "SOURCE_OVERRIDE"]
