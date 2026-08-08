"""The deployment facts, and the ONE place their names are written down.

These are not thresholds. A threshold is a number a formula compares
against, it carries a unit, and it resolves through `Threshold` — P6 O-18
and the G-15 record settle that. Which file the ledger is, which port to
bind, which scenarios to watch: those are composition, decided before any
formula exists, and routing them through the configuration registry would
put deployment identity behind a dial an analyst can turn at runtime.

So they are read from the environment, once, through
`v3/runtime/secrets.py::from_environment` — the single licensed reader —
for exactly the names listed here. What this file CAN read is therefore
derivable from `KEY_IDS` rather than from a search of the source, which is
the same property `required_key_ids` gives the credential side.

Three of the values are refused rather than defaulted:

    ledger path   no default at all. `LedgerStore` refuses one for the
                  reason a default is dangerous (two processes disagreeing
                  about which database is real); this layer refuses to
                  invent one for the same reason, and additionally refuses
                  any path that names a v1 file (R4, `isolation.py`).
    port          defaulted away from v1's 8000, and 8000 itself refused.
    scenarios     defaulted to "every enabled scenario in the geography",
                  which is derived from deployment data rather than listed
                  here, and refused if it names one the geography lacks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

from v3.auth import session as SESSION
from v3.kernel.errors import DomainError
from v3.runtime import geo as GEO
from v3.runtime import secrets as SECRETS
from v3.runtime.loop import DEFAULT_INTERVAL_SEC
from v3.server import isolation

#: WHICH file the v3 ledger is. Required — see the module docstring.
LEDGER_PATH_KEY = "NOROSHI_V3_LEDGER_PATH"
#: WHERE the deployment geography is read from. Defaults to the repo copy.
GEO_PATH_KEY = "NOROSHI_V3_GEO_PATH"
HOST_KEY = "NOROSHI_V3_HOST"
PORT_KEY = "NOROSHI_V3_PORT"
#: Comma-separated scenario ids. Empty means every enabled scenario.
SCENARIOS_KEY = "NOROSHI_V3_SCENARIOS"
INTERVAL_KEY = "NOROSHI_V3_TICK_INTERVAL_SEC"
COOKIE_SECURE_KEY = "NOROSHI_V3_COOKIE_SECURE"
#: `scenario_id:CC` pairs. Which belligerent owns a scenario's sequence
#: chain is the composition root's to supply and is deliberately NOT
#: derived (`v3/runtime/scoring.py::scenarios_for`): production picks it
#: by live spike, and any static rule picks the same country forever.
CHAIN_COUNTRIES_KEY = "NOROSHI_V3_CHAIN_COUNTRIES"

#: 8300 rather than 8000. Distance from v1's port is the point.
DEFAULT_PORT = 8300
#: Loopback by default. A shadow deployment that binds every interface on
#: first run is a shadow deployment somebody else can read.
DEFAULT_HOST = "127.0.0.1"

#: Every environment name this deployment honours. Includes the two auth
#: key ids, which live in `v3/auth/session.py` because the surface that
#: uses them owns their names — listed here so the start-up disclosure can
#: print the whole set from one place.
KEY_IDS: tuple[str, ...] = (
    LEDGER_PATH_KEY, GEO_PATH_KEY, HOST_KEY, PORT_KEY, SCENARIOS_KEY,
    INTERVAL_KEY, COOKIE_SECURE_KEY, CHAIN_COUNTRIES_KEY,
    SESSION.SIGNING_KEY_ID, SESSION.BOOTSTRAP_KEY_ID,
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _flag(raw: str, key: str, fallback: bool) -> bool:
    text = str(raw).strip().lower()
    if not text:
        return fallback
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise DomainError(
        f"{key}={raw!r} is neither true nor false. A misspelt flag that "
        f"silently took its default is how a `Secure` cookie attribute "
        f"comes to be off in production.")


def _pairs(raw: str, key: str) -> dict:
    parsed = {}
    for chunk in str(raw).split(","):
        item = chunk.strip()
        if not item:
            continue
        name, separator, code = item.partition(":")
        if not separator or not name.strip() or not code.strip():
            raise DomainError(
                f"{key} takes `scenario_id:CC` pairs separated by commas, "
                f"got {item!r}")
        parsed[name.strip()] = code.strip().upper()
    return parsed


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """One shadow deployment, as a value.

    Validated at construction rather than at use: a deployment whose port
    collides with v1's should fail before the ledger file is created, not
    after the first tick has written to it.
    """

    ledger_path: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    geo_path: str = str(GEO.DEFAULT_PATH)
    scenario_ids: tuple[str, ...] = ()
    interval_sec: float = DEFAULT_INTERVAL_SEC
    cookie_secure: bool = True
    chain_countries: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ledger_path",
                           isolation.assert_isolated_ledger(self.ledger_path))
        object.__setattr__(self, "port", isolation.assert_isolated_port(
            self.port))
        if not str(self.host).strip():
            raise DomainError("host must be a non-empty address")
        if float(self.interval_sec) <= 0:
            raise DomainError(
                f"interval_sec must be positive, got {self.interval_sec}: a "
                f"non-positive interval is a busy loop holding the ledger's "
                f"write lock")
        object.__setattr__(self, "interval_sec", float(self.interval_sec))
        object.__setattr__(self, "scenario_ids",
                           tuple(dict.fromkeys(
                               str(item).strip()
                               for item in self.scenario_ids
                               if str(item).strip())))
        object.__setattr__(self, "chain_countries",
                           dict(self.chain_countries))

    @property
    def ledger_name(self) -> str:
        """The basename. What the API may disclose; the path is not served."""
        import pathlib
        return pathlib.Path(self.ledger_path).name

    def as_dict(self) -> dict:
        """The operator's view. Includes the path — this is the CLI's."""
        return {"ledger_path": self.ledger_path, "host": self.host,
                "port": self.port, "geo_path": self.geo_path,
                "scenario_ids": list(self.scenario_ids),
                "interval_sec": self.interval_sec,
                "cookie_secure": self.cookie_secure,
                "chain_countries": dict(self.chain_countries)}


def from_environment(source: Optional[Mapping[str, str]] = None
                     ) -> ServerSettings:
    """Build the settings from a snapshot, or from the process environment.

    `source` is an explicit mapping for tests and for a composition root
    that already took ONE snapshot for the whole deployment; `None` means
    "read exactly `KEY_IDS`", which is the production path and goes
    through the single licensed reader.
    """
    material = dict(SECRETS.from_environment(KEY_IDS)) if source is None \
        else dict(source)
    ledger_path = str(material.get(LEDGER_PATH_KEY, "")).strip()
    if not ledger_path:
        raise DomainError(
            f"{LEDGER_PATH_KEY} is not set. The v3 ledger is a separate "
            f"SQLite file from v1's (R4: the old system stays authoritative "
            f"until parity passes), and this layer will not invent a path — "
            f"a default is how two processes come to disagree about which "
            f"database is real. Set it to a file OUTSIDE "
            f"radar/persistence/, e.g. /app/v3data/noroshi_v3.db")
    scenarios = tuple(item.strip() for item
                      in str(material.get(SCENARIOS_KEY, "")).split(",")
                      if item.strip())
    return ServerSettings(
        ledger_path=ledger_path,
        host=str(material.get(HOST_KEY, "") or DEFAULT_HOST).strip(),
        port=int(str(material.get(PORT_KEY, "") or DEFAULT_PORT)),
        geo_path=str(material.get(GEO_PATH_KEY, "")
                     or str(GEO.DEFAULT_PATH)).strip(),
        scenario_ids=scenarios,
        interval_sec=float(str(material.get(INTERVAL_KEY, "")
                               or DEFAULT_INTERVAL_SEC)),
        cookie_secure=_flag(material.get(COOKIE_SECURE_KEY, ""),
                            COOKIE_SECURE_KEY, True),
        chain_countries=_pairs(material.get(CHAIN_COUNTRIES_KEY, ""),
                               CHAIN_COUNTRIES_KEY))


def describe() -> tuple[dict, ...]:
    """Every honoured variable and what it decides. For `--check`."""
    return (
        {"key": LEDGER_PATH_KEY, "required": True,
         "note": "v3 台帳の SQLite ファイル。v1 のファイル名・"
                 "radar/persistence/ 配下は拒否される"},
        {"key": GEO_PATH_KEY, "required": False,
         "note": f"配備地理。既定 {GEO.DEFAULT_PATH}"},
        {"key": HOST_KEY, "required": False,
         "note": f"束縛アドレス。既定 {DEFAULT_HOST}"},
        {"key": PORT_KEY, "required": False,
         "note": f"束縛ポート。既定 {DEFAULT_PORT}。"
                 f"v1 の {isolation.V1_PORT} は拒否される"},
        {"key": SCENARIOS_KEY, "required": False,
         "note": "カンマ区切りのシナリオ ID。空なら地理の有効シナリオ全件"},
        {"key": INTERVAL_KEY, "required": False,
         "note": f"ティック間隔（秒）。既定 {DEFAULT_INTERVAL_SEC}"},
        {"key": COOKIE_SECURE_KEY, "required": False,
         "note": "refresh cookie の Secure 属性。既定 true。"
                 "http で動かす検証時のみ false"},
        {"key": CHAIN_COUNTRIES_KEY, "required": False,
         "note": "`scenario_id:CC` の組。系列連鎖の所有国は導出しない"},
        {"key": SESSION.SIGNING_KEY_ID, "required": False,
         "note": "署名鍵。無ければ auth ルート全件が 503。v3 は生成しない"},
        {"key": SESSION.BOOTSTRAP_KEY_ID, "required": False,
         "note": "利用者 0 件のときだけ使う初期管理者パスワード"},
    )


__all__ = ["ServerSettings", "from_environment", "describe", "KEY_IDS",
           "LEDGER_PATH_KEY", "GEO_PATH_KEY", "HOST_KEY", "PORT_KEY",
           "SCENARIOS_KEY", "INTERVAL_KEY", "COOKIE_SECURE_KEY",
           "CHAIN_COUNTRIES_KEY", "DEFAULT_PORT", "DEFAULT_HOST"]
