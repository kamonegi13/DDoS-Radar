"""The composition root's half of v3's 3-layer resolution.

`v3/config/resolution.py` is the chain; this is who owns it. The division
is the same one the rest of `v3/runtime/` follows — the root owns threads,
clocks, credentials and now configuration layers, and nothing below it
reaches for any of them:

    v3/config/registry.py     WHICH keys, and who reads them. Pure data.
    v3/config/resolution.py   HOW they resolve. Pure of the environment:
                              the snapshot arrives as an argument.
    v3/runtime/config.py      WHERE the snapshot comes from, and the one
                              function that goes and gets it.

The environment read itself is still not here. It is delegated to
`v3/runtime/secrets.py`, the single module the discipline gate licenses to
touch `os.environ`, and it reads exactly the key names the registry
declares — so what this file CAN read is derivable from the registry rather
than from this file, and a key nobody registered cannot be picked up.

**Import is inert**, like every other module in this package. Building a
resolver is an explicit call; importing this one snapshots nothing. A
composition root that reads the environment at import makes every test
process a configured process, which is how the last configuration system
became untestable.
"""
from __future__ import annotations

from typing import Mapping, Optional

from v3.config import registry
from v3.config.resolution import ConfigResolver
from v3.runtime import secrets


def build_resolver(environment: Optional[Mapping[str, str]] = None
                   ) -> ConfigResolver:
    """The chain, with its environment layer filled in.

    `environment` is an explicit mapping for tests and for a deployment
    that layers several stores before calling; `None` means "read the
    process environment for exactly the registered variable keys", which
    is the production path and the only one that touches `os.environ`.
    """
    material = (secrets.from_environment(registry.variable_keys())
                if environment is None else dict(environment))
    return ConfigResolver(environment=material)


def environment_key_names() -> tuple[str, ...]:
    """Every environment variable this file may read. Derived, not listed.

    Served by the start-up disclosure so an operator can see which names
    the deployment will honour without reading the source — and so the
    answer cannot drift from the registry, because it IS the registry.
    """
    return registry.variable_keys()


__all__ = ["build_resolver", "environment_key_names"]
