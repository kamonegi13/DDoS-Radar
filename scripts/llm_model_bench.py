"""LLM model benchmark — empirical comparison harness.

Replays real DDoS-Radar prompts from ``llm_prompts`` against every
candidate model installed on the local Ollama. Scores each call on
parse success, required-field presence, latency, and degenerate-loop
detection.

Output: ``scripts/_bench_<timestamp>.json`` plus a markdown summary
table. The script intentionally lives outside the Flask app so a long
benchmark run cannot affect production scoring.

Usage:
    python scripts/llm_model_bench.py            # default: 30 ok + 30 fail
    python scripts/llm_model_bench.py --n 10     # smaller, faster
    python scripts/llm_model_bench.py --models gemma4:26b,qwen3.5:35b

Run from the host (Ollama at localhost:11434), NOT inside the
container. The container does not have routing to host.docker.internal
in this deployment.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Configuration ───────────────────────────────────────────────────────────

OLLAMA_URL = "http://localhost:11434/api/generate"
# Host filesystem stores a *stale* radar.db; the live one lives in the
# docker volume mounted into the container. Override via --db if you
# already have a fresh export at /tmp/radar_live.db (run
# ``docker cp ddos-radar:/app/radar/persistence/radar.db /tmp/radar_live.db``
# before launching the bench).
DEFAULT_DB_PATH = Path("/tmp/radar_live.db")
FALLBACK_DB_PATH = Path(__file__).resolve().parent.parent / "radar" / "persistence" / "radar.db"
DEFAULT_TIMEOUT = 180  # per-call timeout (sec) — bf16 31b can be slow first call

DB_PATH: Path = DEFAULT_DB_PATH  # overridden in main()

# Default candidate set — every model worth benchmarking for sensor_extract.
# gpt-oss-safeguard / granite-embedding / llama3.1:8b / gemma3:12b excluded:
#   - safeguard is a 2nd-opinion model (different role)
#   - embeddings model is not a chat completer
#   - 8b/12b are below the quality floor we'd ever pick
DEFAULT_MODELS = [
    "gemma4:26b",                    # current production baseline
    "gemma4:31b",                    # vanilla 31b
    "gemma4:31b-coding-mtp-bf16",    # the candidate user proposed
    "qwen3.5:35b",                   # 99% ok track record
    "mistral-small3.2:24b",          # survey-v10 sensor primary
]

# sensor_extract sampling parameters from the live routing config.
SENSOR_EXTRACT_OPTIONS = {
    "temperature": 0.1,
    "num_predict": 512,
    "top_k": 64,
    "top_p": 0.95,
    "repeat_penalty": 1.0,
}

# Required fields the sensor_extract JSON must produce. These mirror
# the prompt's instruction set; missing fields = downstream pipeline
# breakage even if JSON parses.
REQUIRED_FIELDS = (
    "headline",
    "escalation_signal",
)

DEGENERATE_PATTERNS = (
    re.compile(r"(.{1,15}?)(\1){8,}", re.DOTALL),  # 8+ repeats of the same short string
    re.compile(r"(?:[A-Z]{2,3}/){8,}"),             # country-code reps: UA/UA/UA/...
    re.compile(r'":-1,?\s*"[^"]+":-1,?\s*"[^"]+":-1'),  # repeated -1 fields
)


# ── Result types ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CallResult:
    model: str
    prompt_sha: str
    sample_kind: str           # 'ok' or 'fail' (the original outcome)
    duration_ms: float
    raw_output: str
    parsed_ok: bool
    fields_present: tuple[str, ...]
    fields_missing: tuple[str, ...]
    degenerate: bool
    http_error: Optional[str] = None


@dataclass
class ModelStats:
    model: str
    n_total: int = 0
    n_parsed_ok: int = 0
    n_required_complete: int = 0
    n_degenerate: int = 0
    n_http_error: int = 0
    durations_ms: list[float] = field(default_factory=list)
    parse_failures: list[CallResult] = field(default_factory=list)

    @property
    def parse_rate(self) -> float:
        return self.n_parsed_ok / self.n_total if self.n_total else 0.0

    @property
    def field_complete_rate(self) -> float:
        return self.n_required_complete / self.n_total if self.n_total else 0.0

    @property
    def avg_duration_ms(self) -> float:
        ds = self.durations_ms
        return sum(ds) / len(ds) if ds else 0.0

    @property
    def p95_duration_ms(self) -> float:
        if not self.durations_ms:
            return 0.0
        s = sorted(self.durations_ms)
        idx = max(0, int(len(s) * 0.95) - 1)
        return s[idx]


# ── Sampling ────────────────────────────────────────────────────────────────


def sample_prompts(db_path: Path, *, use_case: str = "sensor_extract",
                   n_per_outcome: int = 30) -> list[dict]:
    """Read recent prompts of the given use_case from the live DB.

    Returns a list of dicts: {prompt_sha, prompt_text, outcome,
    sample_kind}. Equal counts of 'ok' and 'parse_failed' so the
    benchmark covers both happy-path and the failure-mode prompts.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    out: list[dict] = []
    for kind in ("ok", "parse_failed"):
        rows = conn.execute(
            """
            SELECT lp.prompt_sha256, lp.prompt_text
            FROM llm_call_log lc
            JOIN llm_prompts lp ON lp.prompt_sha256 = lc.prompt_sha256
            WHERE lc.use_case = ? AND lc.outcome = ?
            ORDER BY lc.ts DESC LIMIT ?
            """,
            (use_case, kind, n_per_outcome * 2),
        ).fetchall()
        seen: set[str] = set()
        for r in rows:
            if r["prompt_sha256"] in seen:
                continue
            seen.add(r["prompt_sha256"])
            out.append({
                "prompt_sha": r["prompt_sha256"],
                "prompt_text": r["prompt_text"],
                "sample_kind": kind,
            })
            if len([p for p in out if p["sample_kind"] == kind]) >= n_per_outcome:
                break
    conn.close()
    return out


# ── Scoring ─────────────────────────────────────────────────────────────────


def _strip_code_fences(text: str) -> str:
    """Some models wrap JSON in ``` fences; tolerate that."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    return text.strip()


def _detect_degenerate(text: str) -> bool:
    if not text or len(text) < 30:
        return False
    for pat in DEGENERATE_PATTERNS:
        if pat.search(text):
            return True
    return False


def score_output(raw: str) -> tuple[bool, tuple[str, ...], tuple[str, ...], bool]:
    """Return (parsed_ok, fields_present, fields_missing, degenerate)."""
    degenerate = _detect_degenerate(raw)
    cleaned = _strip_code_fences(raw)
    try:
        parsed = json.loads(cleaned)
    except Exception:
        # Try fishing for the first {...} block — some models prepend prose.
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not m:
            return False, (), tuple(REQUIRED_FIELDS), degenerate
        try:
            parsed = json.loads(m.group(0))
        except Exception:
            return False, (), tuple(REQUIRED_FIELDS), degenerate
    if not isinstance(parsed, dict):
        return False, (), tuple(REQUIRED_FIELDS), degenerate
    present = tuple(k for k in REQUIRED_FIELDS if k in parsed)
    missing = tuple(k for k in REQUIRED_FIELDS if k not in parsed)
    return True, present, missing, degenerate


# ── Ollama call ─────────────────────────────────────────────────────────────


def call_ollama(model: str, prompt: str, *,
                timeout: int = DEFAULT_TIMEOUT,
                use_format_json: bool = True,
                use_think_false: bool = True) -> tuple[str, float, Optional[str]]:
    """Single Ollama generate. Returns (raw_text, duration_ms, http_error).

    Methodology fix (2026-05-10 round 1): production's ``llm_analyze_json``
    passes ``format='json'`` to Ollama (structured-output mode). Without
    that flag gemma family produces empty responses. We default to
    ``use_format_json=True`` to match production.

    Methodology fix (2026-05-10 round 2): gemma4 family supports thinking
    mode and burns the entire token budget on internal CoT before emitting
    any visible response. Smoke test confirmed gemma4:26b returns 0 chars
    without ``think=false`` but valid JSON in 1.8s with it. Production
    ``llm_analyze_json`` does NOT pass ``think=false`` — that's a real
    production bug. Bench now defaults to ``use_think_false=True`` to give
    every model a fair chance and to indicate the production fix path.

    stdlib-only so the script runs on a vanilla host Python without
    needing to install a venv.
    """
    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": SENSOR_EXTRACT_OPTIONS,
    }
    if use_format_json:
        payload["format"] = "json"
    if use_think_false:
        payload["think"] = False
    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=body_bytes,
        headers={"Content-Type": "application/json"},
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dur = (time.time() - start) * 1000
            if resp.status != 200:
                return "", dur, f"HTTP {resp.status}"
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            text = (data.get("response") or "").strip()
            if not text:
                text = (data.get("thinking") or "").strip()
            return text, dur, None
    except urllib.error.HTTPError as e:
        body_snippet = ""
        try:
            body_snippet = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        return "", (time.time() - start) * 1000, f"HTTP {e.code}: {body_snippet}"
    except Exception as e:
        msg = str(e)
        if "timed out" in msg.lower():
            return "", (time.time() - start) * 1000, "timeout"
        return "", (time.time() - start) * 1000, f"exception: {msg[:120]}"


# ── Main benchmark ──────────────────────────────────────────────────────────


def run_bench(*, models: list[str], n_per_outcome: int,
              use_case: str, timeout: int) -> dict:
    samples = sample_prompts(
        DB_PATH, use_case=use_case, n_per_outcome=n_per_outcome,
    )
    print(f"[bench] sampled {len(samples)} prompts "
          f"({sum(1 for s in samples if s['sample_kind']=='ok')} ok, "
          f"{sum(1 for s in samples if s['sample_kind']=='parse_failed')} fail)")
    print(f"[bench] models: {models}")
    print(f"[bench] expected calls: {len(samples) * len(models)}")

    stats: dict[str, ModelStats] = {m: ModelStats(model=m) for m in models}
    all_results: list[CallResult] = []

    for i, sample in enumerate(samples):
        for m in models:
            print(f"  [{i+1:>3d}/{len(samples)}] {m:35s} "
                  f"({sample['sample_kind']:<12s})...", end=" ", flush=True)
            raw, dur, http_err = call_ollama(
                m, sample["prompt_text"], timeout=timeout)
            if http_err:
                stats[m].n_total += 1
                stats[m].n_http_error += 1
                print(f"ERR {http_err[:40]}")
                cr = CallResult(
                    model=m, prompt_sha=sample["prompt_sha"],
                    sample_kind=sample["sample_kind"],
                    duration_ms=dur, raw_output="",
                    parsed_ok=False, fields_present=(),
                    fields_missing=tuple(REQUIRED_FIELDS),
                    degenerate=False, http_error=http_err,
                )
                all_results.append(cr)
                continue
            parsed_ok, present, missing, degen = score_output(raw)
            cr = CallResult(
                model=m, prompt_sha=sample["prompt_sha"],
                sample_kind=sample["sample_kind"],
                duration_ms=dur, raw_output=raw,
                parsed_ok=parsed_ok, fields_present=present,
                fields_missing=missing, degenerate=degen,
            )
            all_results.append(cr)
            s = stats[m]
            s.n_total += 1
            s.durations_ms.append(dur)
            if parsed_ok:
                s.n_parsed_ok += 1
                if not missing:
                    s.n_required_complete += 1
            else:
                s.parse_failures.append(cr)
            if degen:
                s.n_degenerate += 1
            tag = "OK " if parsed_ok and not missing else (
                "FLD" if parsed_ok else "FAIL")
            deg = " DEGEN" if degen else ""
            print(f"{tag}{deg} {dur:>6.0f}ms")

    return {
        "started_at": dt.datetime.now().isoformat(),
        "use_case": use_case,
        "n_prompts": len(samples),
        "stats": {
            m: {
                "n_total":              s.n_total,
                "n_parsed_ok":          s.n_parsed_ok,
                "n_required_complete":  s.n_required_complete,
                "n_degenerate":         s.n_degenerate,
                "n_http_error":         s.n_http_error,
                "parse_rate":           round(s.parse_rate, 4),
                "field_complete_rate":  round(s.field_complete_rate, 4),
                "avg_duration_ms":      round(s.avg_duration_ms, 1),
                "p95_duration_ms":      round(s.p95_duration_ms, 1),
            }
            for m, s in stats.items()
        },
        "raw_results_count": len(all_results),
    }


def render_summary(report: dict) -> str:
    """Return a markdown-ish ASCII table for terminal output."""
    lines = []
    lines.append(f"\n=== LLM bench summary ({report['use_case']}, "
                 f"{report['n_prompts']} prompts) ===\n")
    header = (f"{'model':40s} {'parse':>7s} {'fields':>8s} "
              f"{'degen':>7s} {'http_err':>9s} {'avg_ms':>8s} {'p95_ms':>8s}")
    lines.append(header)
    lines.append("-" * len(header))
    rows = sorted(report["stats"].items(),
                   key=lambda x: -x[1]["field_complete_rate"])
    for m, s in rows:
        lines.append(
            f"{m:40s} "
            f"{s['parse_rate']*100:>6.1f}% "
            f"{s['field_complete_rate']*100:>7.1f}% "
            f"{s['n_degenerate']:>7d} "
            f"{s['n_http_error']:>9d} "
            f"{s['avg_duration_ms']:>8.0f} "
            f"{s['p95_duration_ms']:>8.0f}"
        )
    lines.append("")
    lines.append("ranked by field_complete_rate (parse_ok AND all "
                 "required fields present)")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=30,
                        help="prompts per outcome (ok / parse_failed); "
                             "total = 2*n")
    parser.add_argument(
        "--models", type=str, default=",".join(DEFAULT_MODELS),
        help="comma-separated model list",
    )
    parser.add_argument("--use-case", type=str, default="sensor_extract")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--out", type=str, default="")
    parser.add_argument("--db", type=str, default="")
    args = parser.parse_args()

    if args.db:
        db_path = Path(args.db)
    elif DEFAULT_DB_PATH.exists():
        db_path = DEFAULT_DB_PATH
    else:
        db_path = FALLBACK_DB_PATH
    if not db_path.exists():
        raise SystemExit(f"DB not found at {db_path}; run "
                         f"`docker cp ddos-radar:/app/radar/persistence/radar.db "
                         f"/tmp/radar_live.db` first")

    print(f"[bench] using DB: {db_path}")
    # Patch the module-level DB path so sample_prompts uses the chosen one.
    global DB_PATH  # noqa: PLW0603
    DB_PATH = db_path

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    report = run_bench(
        models=models, n_per_outcome=args.n,
        use_case=args.use_case, timeout=args.timeout,
    )

    out_path = (Path(args.out) if args.out else
                Path(__file__).resolve().parent /
                f"_bench_{int(time.time())}.json")
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(render_summary(report))
    print(f"\n[bench] wrote {out_path}")


if __name__ == "__main__":
    main()
