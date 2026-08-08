"""Serving `v3/ui/`. One rule per file that exists, and no catch-all.

A `/<path:filename>` rule would be shorter and is what most Flask apps
do. It is refused here for two reasons that are the same reason twice:

* **it competes with the API.** Werkzeug's specificity ordering usually
  puts a static rule first, but "usually" is the property a route table
  should not depend on. The API's paths and the page's assets would then
  be resolved by a sort order nobody declared.
* **a missing file becomes a 404 instead of a boot failure.** The page is
  thirteen files that must all be present; a deployment that shipped the
  HTML without `client.js` should fail to compose, not serve an inert
  page to an analyst who then reports that "nothing loads".

So the served set is enumerated from the directory at composition time —
derived, like `required_key_ids`, rather than listed, so it cannot drift
from what is on disk — and `index.html` missing is a `DomainError`.

The page's own references decide the mount point: assets are relative
(`<link href="v3.css">`) and the API prefix is absolute (`/api/v3` in
`client.js`), so the root is where the page works with no rewriting.
"""
from __future__ import annotations

import pathlib
from typing import Iterable, Optional

from v3.kernel.errors import DomainError

#: `v3/ui/`. Resolved from this file so a working directory cannot move it.
UI_DIR = pathlib.Path(__file__).resolve().parents[1] / "ui"
INDEX_NAME = "index.html"

#: Suffixes the page is made of. A file with any other suffix in the
#: directory is served too — the list is for the content type, not for
#: admission, because admission is "it is a file in this directory".
_CONTENT_TYPES = {".html": "text/html; charset=utf-8",
                  ".css": "text/css; charset=utf-8",
                  ".js": "text/javascript; charset=utf-8"}


def asset_names(directory: Optional[pathlib.Path] = None) -> tuple[str, ...]:
    """Every file in the UI directory, sorted. Refuses a directory with no
    index — see the module docstring."""
    base = UI_DIR if directory is None else pathlib.Path(directory)
    if not base.is_dir():
        raise DomainError(
            f"the frontend directory {base} does not exist. The page is not "
            f"optional: P8 makes it the analyst's loop, and a deployment "
            f"serving only the API is a deployment nobody can use.")
    names = tuple(sorted(item.name for item in base.iterdir()
                         if item.is_file()))
    if INDEX_NAME not in names:
        raise DomainError(
            f"{base} has no {INDEX_NAME}. Every other asset is loaded BY "
            f"that document, so its absence is a page that cannot start, "
            f"served as a 404 nobody attributes to the deployment.")
    return names


def content_type(name: str) -> Optional[str]:
    return _CONTENT_TYPES.get(pathlib.Path(name).suffix.lower())


def register(app, *, directory: Optional[pathlib.Path] = None,
             names: Optional[Iterable[str]] = None) -> tuple[str, ...]:
    """Add `/` and one rule per asset. Returns what was mounted.

    Flask is imported inside the function, the same contract
    `v3/api/binding.py` holds: this module stays importable in an
    environment with no web framework, which is how its tests run.
    """
    from flask import send_from_directory

    base = UI_DIR if directory is None else pathlib.Path(directory)
    served = tuple(names) if names is not None else asset_names(base)

    def _view(asset: str):
        def view():
            response = send_from_directory(str(base), asset)
            declared = content_type(asset)
            if declared:
                response.headers["Content-Type"] = declared
            return response
        view.__name__ = f"v3_ui_{asset.replace('.', '_').replace('-', '_')}"
        return view

    app.add_url_rule("/", endpoint="v3_ui_index", methods=["GET"],
                     view_func=_view(INDEX_NAME))
    for asset in served:
        app.add_url_rule(f"/{asset}", endpoint=f"v3_ui_{asset}",
                         methods=["GET"], view_func=_view(asset))
    return served


__all__ = ["UI_DIR", "INDEX_NAME", "asset_names", "content_type", "register"]
