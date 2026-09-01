"""The Flask application. Thin, and the only file here that knows the word.

`v3/api/binding.py` already holds the web boundary for the API — it turns
a Flask request into an `ApiRequest` and back — so this file has exactly
three jobs: create the app, register that blueprint with the composition
root's factories, and mount the page. It contains no route logic, no
projection and no error assembly, for the same reason the binding does
not: an error body assembled here is the exact place the NP7 sentence
went missing before (G-13).

The one thing it adds to every response is `X-Noroshi-Mode: shadow`. A v3
answer is a second opinion until parity passes (R4), and an operator who
has two tabs open should be able to tell them apart without reading the
port number.

Flask is imported inside `create_app`, the same contract every other v3
module holds: importing this module costs nothing and works in an
environment with no web framework.
"""
from __future__ import annotations

from v3.kernel.errors import DomainError
from v3.server import ui as UI
from v3.server.composition import MODE_HEADER, MODE_SHADOW

#: The app's import name. Not `__name__`: Flask uses it to locate a
#: `static/` and `templates/` folder, and this package has neither — a
#: default static folder would be a second, unenumerated way to serve
#: files, which is exactly what `v3/server/ui.py` refuses to have.
APP_NAME = "noroshi_v3"


def create_app(deployment, *, serve_ui: bool = True):
    """Compose the blueprint and the page onto one Flask app.

    `deployment` is a `v3.server.composition.Deployment`. Taking the whole
    thing rather than four callables is deliberate: the read factory, the
    write factory, the principal resolver and the cookie posture must all
    come from ONE composed deployment, and four arguments is four chances
    to hand in three from one and one from another.
    """
    from flask import Flask

    from v3.api.binding import create_blueprint

    if deployment is None:
        raise DomainError("create_app needs a composed Deployment")

    app = Flask(APP_NAME, static_folder=None, template_folder=None)
    app.register_blueprint(create_blueprint(
        deployment.read_context,
        principal_factory=deployment.principal_factory(),
        write_context_factory=deployment.write_context,
        cookie_secure=deployment.settings.cookie_secure))

    if serve_ui:
        UI.register(app)

    @app.after_request
    def _declare_mode(response):
        response.headers[MODE_HEADER] = MODE_SHADOW
        return response

    return app


def mounted_paths(app) -> tuple[str, ...]:
    """Every rule the app answers. For the start-up disclosure."""
    return tuple(sorted(rule.rule for rule in app.url_map.iter_rules()))


__all__ = ["create_app", "mounted_paths", "APP_NAME"]
