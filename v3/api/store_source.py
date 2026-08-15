"""Follow `LedgerStore` across modules, or fail loudly. One resolver.

Both API seams audit the store by AST rather than by trust:

    v3/api/readonly.py   which methods hold the read-only handle, so the
                         forwarded set is derived, not remembered (A-01).
    v3/api/writeonly.py  that `append_command` writes `command_record` and
                         that nothing else does (G-15 / S2-PROP-019).

Both used to parse ONE file for `class LedgerStore`. WP-4.1c refused to
split `store.py` for the line limit precisely because of that: a method
moved into a module neither audit parsed would have vanished from both
classifications **without either of them failing** — the read seam would
stop forwarding a reader (a projection quietly disappears) and the write
seam would stop noticing a second writer of the command table. A drive-by
split would have silently disabled the two checks that exist to prevent
silent disabling.

So the split came with this module, and it does three things the old
single-file parse did not:

1. **It follows the class.** The base chain is resolved from the source —
   `LedgerStore`'s bases, then theirs — through each module's own import
   bindings, so where a method lives is a fact the audit discovers rather
   than a list somebody keeps in step.
2. **An unresolvable base is a failure, not an omission.** A base the
   resolver cannot find a module for raises. The dangerous direction is
   always "found fewer things than there are", so that direction is the
   one that stops the build.
3. **There is a floor.** `METHOD_FLOOR` records how many methods the chain
   held when it was last reviewed. Finding fewer raises, whatever the
   reason — a hidden module, a deleted method, a renamed class. A split
   that shrinks audit coverage is a red build; a legitimate removal is a
   deliberate edit to one number here.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional, Sequence

from v3.kernel.errors import DomainError

#: Where the chain starts. Everything else is derived from the source.
LEDGER_DIR = Path(__file__).resolve().parent.parent / "ledger"
ROOT_MODULE = LEDGER_DIR / "store.py"
STORE_CLASS = "LedgerStore"

#: The floor, reviewed 2026-08-08 when WP-4.1f added a fifth module to
#: the chain (`store_attention.py`: the S8 rank ledger), on top of
#: WP-3.3's fourth and WP-4.1b's three-way split. Counts EVERY
#: function def on the chain, public and private, because the private ones
#: are what the read seam's call-graph fixpoint propagates through — a
#: hidden `_entity_rows` would reclassify its public callers as writers by
#: omission, which shrinks the read surface without a word.
#: Raised 67 -> 68 on 2026-08-09 for `baseline_series_values` (§7-2 #135,
#: the cold-baseline warm-up read). The floor is meant to be raised by
#: hand exactly like this: the method was added and committed without a
#: READ_METHODS entry, and the audit refused the build rather than
#: silently classifying it as neither — which is the G-01 shape and the
#: reason this gate exists.
#: Raised 68 -> 69 on 2026-08-09 for `_version_on`, the private schema-
#: version read that the per-thread write handle needed: `_migrate` runs
#: at construction and must read the version off the connection it was
#: HANDED, not off one a thread-keyed lookup might open underneath it.
#: The same change moved the handle methods to `store_connections.py` —
#: a SIXTH module on the chain — and the count is unchanged by that,
#: which is the property this floor exists to prove.
#: Raised 69 -> 74 on 2026-08-15 for WP-0.4 v2: the five calibration
#: methods the S9 runner needs (`append_fn_draft`, `fn_drafts`,
#: `pending_fn_draft_counts`, `append_s9_run`, `latest_s9_run_at`), all
#: public, all classified in the two seams.
METHOD_FLOOR = 74
#: The public half of the same count. Named separately because the two
#: seams partition PUBLIC methods (`READ_METHODS` / `WRITE_METHODS`), and
#: a public method that stopped being seen is the one an analyst notices.
PUBLIC_METHOD_FLOOR = 63


def _bindings(tree: ast.Module) -> dict:
    """{local name -> dotted module} for every `from X import Y` in a file."""
    found: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                found[alias.asname or alias.name] = node.module
    return found


def _module_path(dotted: str) -> Optional[Path]:
    """`v3.ledger.store_entities` -> its file, if it is one of ours."""
    if not dotted.startswith("v3."):
        return None
    candidate = LEDGER_DIR.parent.parent / (dotted.replace(".", "/") + ".py")
    return candidate if candidate.exists() else None


def _base_names(node: ast.ClassDef) -> list:
    names = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
        else:
            raise DomainError(
                f"{node.name} has a base the audit cannot name "
                f"({ast.dump(base)[:60]}...). An unfollowable base is a set "
                f"of methods that would stop being audited in silence, "
                f"which is the failure mode both seams exist to prevent.")
    return names


def _class_in(tree: ast.Module, name: str) -> Optional[ast.ClassDef]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def resolve_chain(root: Optional[Path] = None) -> tuple:
    """(methods, modules) for `LedgerStore` and every base it declares.

    `methods` is `{name: FunctionDef}` merged across the chain, with the
    most derived definition winning — Python's own MRO for the shape used
    here (mixins carrying no state). `modules` is every file actually
    parsed, so a caller can report WHICH files the audit covered rather
    than assert that it covered enough.
    """
    start = Path(root) if root is not None else ROOT_MODULE
    pending = [(start, STORE_CLASS)]
    seen: set = set()
    modules: list = []
    #: Bases first, then the derived class, so a derived override wins.
    layers: list = []
    while pending:
        path, class_name = pending.pop(0)
        marker = (str(path), class_name)
        if marker in seen:
            continue
        seen.add(marker)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = _class_in(tree, class_name)
        if node is None:
            raise DomainError(
                f"the audit cannot find class {class_name!r} in {path.name}: "
                f"the store moved and this check would otherwise carry on "
                f"reporting a clean partition of nothing")
        if path not in modules:
            modules.append(path)
        layers.append({item.name: item for item in node.body
                       if isinstance(item, (ast.FunctionDef,
                                            ast.AsyncFunctionDef))})
        bindings = _bindings(tree)
        for base in _base_names(node):
            dotted = bindings.get(base)
            base_path = None if dotted is None else _module_path(dotted)
            if base_path is None:
                raise DomainError(
                    f"{class_name} inherits {base!r}, which the audit cannot "
                    f"resolve to a module under v3/ (import binding: "
                    f"{dotted!r}). Its methods would be invisible to the "
                    f"read and write seams — the exact way a split makes an "
                    f"audit stop checking without failing.")
            pending.append((base_path, base))

    methods: dict = {}
    for layer in reversed(layers):      # bases first, derived last
        methods.update(layer)
    return methods, tuple(modules)


def class_methods(root: Optional[Path] = None,
                  extra_sources: Optional[Sequence[Path]] = None, *,
                  floor: Optional[int] = None,
                  public_floor: Optional[int] = None) -> dict:
    """The chain's methods, floor-checked. Raises rather than under-reporting.

    The floor is checked on EVERY call, including one against a synthetic
    root. A check that switched itself off for anything but the production
    tree would be a check that a test could not exercise, and an
    unexercised guard is the thing this whole module distrusts. A test
    building a two-method chain states `floor=` explicitly, which is a
    visible choice rather than an inherited exemption.
    """
    methods, modules = resolve_chain(root)
    for path in (extra_sources or ()):
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        node = _class_in(tree, STORE_CLASS)
        if node is not None:
            methods.update({item.name: item for item in node.body
                            if isinstance(item, (ast.FunctionDef,
                                                 ast.AsyncFunctionDef))})
    _check_floor(methods, modules, floor=floor, public_floor=public_floor)
    return methods


def public_methods(methods: dict) -> set:
    """Public, non-property method names — the two seams' partition domain."""
    public: set = set()
    for name, node in methods.items():
        if name.startswith("_"):
            continue
        if any(isinstance(dec, ast.Name) and dec.id == "property"
               for dec in node.decorator_list):
            continue
        public.add(name)
    return public


def _check_floor(methods: dict, modules: tuple, *,
                 floor: Optional[int] = None,
                 public_floor: Optional[int] = None) -> None:
    """THE assertion a split must not be able to slip past."""
    required = METHOD_FLOOR if floor is None else floor
    required_public = (PUBLIC_METHOD_FLOOR if public_floor is None
                       else public_floor)
    found, public = len(methods), len(public_methods(methods))
    if found < required or public < required_public:
        raise DomainError(
            f"the {STORE_CLASS} audit found {found} methods ({public} "
            f"public) across {[p.name for p in modules]}, below the recorded "
            f"floor of {required} ({required_public} public). Either a "
            f"method was hidden in a module the base chain does not reach — "
            f"which is how a split makes the read and write seams stop "
            f"checking without failing — or one was deliberately removed, in "
            f"which case lower the floor in v3/api/store_source.py in the "
            f"same commit and say why.")


def coverage() -> dict:
    """What the audit actually parsed. Served by the seam tests as evidence."""
    methods, modules = resolve_chain()
    return {"modules": [path.name for path in modules],
            "methods": len(methods),
            "public_methods": len(public_methods(methods)),
            "floor": METHOD_FLOOR, "public_floor": PUBLIC_METHOD_FLOOR}


__all__ = ["LEDGER_DIR", "ROOT_MODULE", "STORE_CLASS", "METHOD_FLOOR",
           "PUBLIC_METHOD_FLOOR", "resolve_chain", "class_methods",
           "public_methods", "coverage"]
