"""`python -m v3.server` — the supported invocation, and the only one.

This file exists so the entrypoint has a name that cannot be confused
with a module. `python -m v3.server.main` would import `v3` and
`v3.server` and then run `main.py` a second time as `__main__`; that file
refuses it. Here, the refusal is not needed and would be wrong: this IS
`__main__`, it imports the entrypoint by its real name, and calls it.
"""
from v3.server.main import main

raise SystemExit(main())
