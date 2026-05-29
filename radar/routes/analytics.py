"""radar.routes.analytics -- Read-only analytics, report, and data-status endpoints."""
from __future__ import annotations
import time
import datetime
from flask import jsonify, request
from radar.auth import require_role
from radar.config import (
    ADAPTIVE_ZSCORE_ENABLED, ADAPTIVE_ZSCORE_MIN_SAMPLES,
    SEQUENCE_WINDOW,
    C_MEDIUM_WINDOW_DAYS, C_MEDIUM_MISS_THRESHOLD,
    C_MEDIUM_DELTA_MISS, C_MEDIUM_MIN_SWITCHES,
    C_MEDIUM_DELTA_MISS_SHADOW,
    SHOW_BACKGROUND_TL,
)
from radar import state as st
from radar.state import _global_cache_lock, ALERT_TIMELINE_MAX
from radar.database import db as _db
from radar.models import RationaleEntry
from radar.scoring import (
    compute_sequence_bonus, compute_weight_utilization,
    compute_weight_utilization_timeseries, derive_tl,
    Signal, ScenarioContribution,
)
import radar.routes as _routes
from radar.routes import bp, _safe_int, _country_param

# Phase 7.5c (audit Security H1): defence-in-depth role gate. Every
# route in this module is read-only and surfaces aggregated OSINT data
# that, while same-origin and JWT-gated by the global before_request
# hook, deserves an explicit per-route check so a future hook bypass
# (selective exception, decorator drop) cannot accidentally expose
# scoring/intel/calibration data to anonymous clients. The role tuple
# matches the global gate ("admin", "analyst", "viewer") — these
# endpoints intentionally accept all three roles.
_ANALYTICS_READ_ROLES = ("admin", "analyst", "viewer")
_analytics_read = require_role(*_ANALYTICS_READ_ROLES)

@bp.route("/api/data_status", methods=["GET"])
@_analytics_read
def data_status():
    now = time.time(); sensors_status = []
    for s in _routes.registry._sensors.values():
        log = s.get_fetch_log()
        # Sanitize last_error: strip stack traces, truncate to 100 chars
        err = s._last_error or ""
        if "\n" in err:
            err = err.split("\n")[0]
        err = err[:100]
        entry = {
            "sensor": s.name, "domain": s.domain, "enabled": s.enabled, "health": s.health,
            "poll_interval_sec": s.poll_interval, "cache_age_sec": round(now - s._cache_time) if s._cache_time else None,
            "cache_size_chars": len(str(s._cache)), "last_error": err or None, "last_fetch": log[-1] if log else None, "fetch_log": log,
        }
        # Optional per-sensor upstream health (e.g. CtLogSensor crt.sh probe state)
        if hasattr(s, "upstream_health") and callable(getattr(s, "upstream_health")):
            try:
                entry["upstream"] = s.upstream_health()
            except Exception:
                pass
        sensors_status.append(entry)
    return jsonify({"ts": datetime.datetime.now().isoformat(), "sensors": sensors_status})

@bp.route("/api/sensor_reliability", methods=["GET"])
@_analytics_read
def sensor_reliability():
    """Per-sensor fetch reliability over a given time window (default 24h, max 168h)."""
    hours = _safe_int(request.args.get("hours", 24), 24, min_val=1, max_val=168)
    rows = _db.fetch_log_reliability(hours=hours)
    return jsonify({"ts": datetime.datetime.now().isoformat(), "hours": hours, "sensors": rows})

@bp.route("/api/alert_timeline", methods=["GET"])
@_analytics_read
def api_alert_timeline():
    limit = _safe_int(request.args.get("limit", 288), 288, min_val=1, max_val=288)
    return jsonify({"ts": datetime.datetime.now().isoformat(), "count": _db.alert_count(), "timeline": _db.alert_list(limit)})


@bp.route("/api/sitrep", methods=["GET"])
@_analytics_read
def api_sitrep():
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    _tl = _db.alert_list()
    if not _tl:
        return jsonify({"ts": now_ts.isoformat(), "text": "No data available yet.", "summary": {}})

    recent, latest, oldest = _tl[-12:], _tl[-1], _tl[0]
    span_min = round((latest["ts"] - oldest["ts"]) / 60) if len(_tl) > 1 else 0
    levels = [e["threat_level"] for e in recent]
    min_d, max_d, avg_d = min(levels), max(levels), round(sum(levels) / len(levels), 1)
    
    conv_counts = {}
    for e in recent:
        lv = e.get("convergence_level", "NONE")
        conv_counts[lv] = conv_counts.get(lv, 0) + 1
    dominant_conv = max(conv_counts, key=lambda k: conv_counts[k])
    
    active_domains = []
    if latest.get("domain_cyber", 0) > 0: active_domains.append("CYBER")
    if latest.get("domain_physical", 0) > 0: active_domains.append("PHYSICAL")
    if latest.get("domain_info", 0) > 0: active_domains.append("INFO")
    
    trend = "INSUFFICIENT DATA"
    if len(levels) >= 3:
        trend_val = latest["threat_level"] - levels[0]
        trend = "ESCALATING" if trend_val < 0 else "DE-ESCALATING" if trend_val > 0 else "STABLE"

    core = latest.get("core_theater") or "UNKNOWN"
    note = latest.get("system_note", "")
    
    text_lines = [
        "UNCLASSIFIED // FOR OFFICIAL USE ONLY",
        "TACTICAL SITUATION REPORT (SITREP)",
        f"DTG: {now_ts.strftime('%d%H%MZ %b %Y').upper()}",
        "--------------------------------------------------",
        "1. OVERALL ASSESSMENT",
        f"   CURRENT THREAT LEVEL : LEVEL {latest['threat_level']} [{trend}]",
        f"   PRIMARY THEATER      : {core}",
        f"   CONVERGENCE STATE    : {dominant_conv.replace('_', ' ')}",
        f"   OBSERVATION WINDOW   : {span_min} MIN / {len(_tl)} CYCLES",
        "",
        "2. DOMAIN ACTIVITY (LAST 1H)",
        f"   THREAT RANGE         : LV {min_d} - LV {max_d} (AVG: {avg_d})",
        f"   ACTIVE DOMAINS       : {', '.join(active_domains) if active_domains else 'NONE'}",
    ]
    
    degraded = latest.get("degraded_theaters", [])
    if degraded: 
        text_lines += [f"   CRITICAL OUTAGES     : {', '.join(degraded)}"]
    
    if latest.get("is_coordinated"): 
        text_lines += ["   WARNING              : COORDINATED MULTI-FRONT ACTIVITY DETECTED"]

    text_lines += [
        "",
        "3. SYSTEM RATIONALE & ANALYST NOTE",
        f"   {note}" if note else "   NO ADDITIONAL RATIONALE PROVIDED.",
        "",
        "4. RECOMMENDATION",
        "   System assessment is probabilistic. Human-in-the-loop (HITL) verification required.",
        "--------------------------------------------------"
    ]

    return jsonify({
        "ts": now_ts.isoformat(), 
        "text": "\n".join(text_lines),
        "summary": {
            "threat_current": latest["threat_level"],
            "threat_trend": trend, 
            "threat_min_1h": min_d,
            "threat_max_1h": max_d,
            "threat_avg_1h": avg_d, 
            "convergence": dominant_conv, 
            "active_domains": active_domains, 
            "core_theater": core,
            # ADR-V2-006 A-2: dual-write `core_country` alongside legacy `core_theater`.
            "core_country": core,
            "span_minutes": span_min,
            "cycle_count": len(_tl)
        },
    })

# ─────────────────────────────────────────────────────────────────────────────
# ── Advanced Analytics Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/api/sequence_chain", methods=["GET"])
@_analytics_read
def api_sequence_chain():
    """
    Return escalation chain status for all countries.
    Query parameter: ?country=TW (omit for all countries; legacy ?theater= still accepted, recorded via SR4 telemetry).
    """
    theater_param = _country_param("/api/sequence_chain").upper()
    now = time.time()
    result = {}
    theaters = [theater_param] if theater_param else _db.seq_distinct_theaters()
    for th in theaters:
        bonus, status, chain = compute_sequence_bonus(th)
        cutoff = now - SEQUENCE_WINDOW
        events = _db.seq_events_since(th, cutoff)
        result[th] = {
            "sequence_bonus":  bonus,
            "chain_status":    status,
            "chain_found":     chain,
            "events":          [
                {"ts": e["ts"], "dt": datetime.datetime.fromtimestamp(e["ts"]).isoformat(),
                 "type": e["type"], "meta": e["meta"]}
                for e in sorted(events, key=lambda x: x["ts"])
            ],
            "window_hours": SEQUENCE_WINDOW // 3600,
        }
    return jsonify({"ts": datetime.datetime.now().isoformat(), "chains": result})


@bp.route("/api/deep_analytics", methods=["GET"])
@_analytics_read
def api_deep_analytics():
    """
    Detailed endpoint for deep analysis results.
    Returns velocity/acceleration/ambush/narrative/ISR/AIS/blockade_index.
    """
    _default_theater = (
        st.global_cache.get("strategic", {}).get("core_theater")
        or ""
    )
    theater_param = (_country_param("/api/deep_analytics") or _default_theater).upper()
    if not theater_param:
        return jsonify({"error": "country required (no focused scenario resolved)"}), 400
    ts_series = _db.ts_get(theater_param)
    velocity   = _routes.engine.compute_velocity(ts_series)
    acc        = _routes.engine.compute_acceleration(ts_series)
    is_ambush, ambush_z, _, _ = _routes.engine.detect_ambush_pattern(ts_series)
    seq_bonus, seq_status, seq_chain = compute_sequence_bonus(theater_param)

    narrative_sensor = _routes.registry.get("rss_narrative")
    narrative_info   = narrative_sensor.get_cache().get("narratives", {}).get(theater_param, {}) if narrative_sensor else {}
    isr_sensor       = _routes.registry.get("isr_hotspot")
    isr_info         = isr_sensor.get_cache().get("isr_data", {}).get(theater_param, {}) if isr_sensor else {}
    ais_sensor       = _routes.registry.get("ais_maritime")
    ais_gaps         = ais_sensor.get_cache().get("dark_gaps", []) if ais_sensor else []
    ais_stat         = ais_sensor.get_cache().get("stationary_anomalies", []) if ais_sensor else []

    # Blockade Index v9: (DDoS intensity × RIPE delay) / Check-Host success rate
    strategic    = st.global_cache.get("strategic", {})
    analytics_v9 = strategic.get("analytics", {})
    core_spike_v = strategic.get("threat_breakdown", {}).get("core_spike_val", 0.0)
    is_degraded  = theater_param in strategic.get("degraded_theaters", [])
    # Use v9 blockade_index from cache if available, otherwise recompute with compute_blockade_index
    if "blockade_index" in analytics_v9:
        blockade_idx = analytics_v9["blockade_index"]
    else:
        bgp_s   = _routes.registry.get("ripe_bgp")
        ch_s    = _routes.registry.get("check_host")
        ripe_drop = bgp_s.get_cache().get("routing_stats", {}).get(theater_param, {}).get("drop_pct", 0.0) if bgp_s else 0.0
        ch_rate   = ch_s.get_cache().get("check_host", {}).get(theater_param, {}).get("theater_success_rate") if ch_s else None
        blockade_idx = _routes.engine.compute_blockade_index(core_spike_v, ripe_drop, ch_rate)

    # Velocity trend (format time series for response)
    velocity_series = []
    for i in range(1, len(ts_series)):
        dt = ts_series[i][0] - ts_series[i-1][0]
        if dt > 0:
            v = (ts_series[i][1] - ts_series[i-1][1]) / dt
            velocity_series.append({
                "ts": ts_series[i][0],
                "dt": datetime.datetime.fromtimestamp(ts_series[i][0]).isoformat(),
                "velocity": round(v, 6),
                "spike_val": ts_series[i][1],
            })

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "theater": theater_param,
        # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
        "country": theater_param,
        "acceleration_engine": {
            "velocity":      round(velocity, 6),
            "acceleration":  round(acc, 8),
            "is_ambush":     is_ambush,
            "ambush_z_score": ambush_z,
            "velocity_series": velocity_series[-20:],
        },
        "sequence_scorer": {
            "bonus":  seq_bonus,
            "status": seq_status,
            "chain":  seq_chain,
            "events": [
                {"ts": e["ts"], "dt": datetime.datetime.fromtimestamp(e["ts"]).isoformat(),
                 "type": e["type"]}
                for e in sorted(_db.seq_all_events(theater_param), key=lambda x: x["ts"])
            ],
        },
        "narrative_burst": {
            "z_score":         narrative_info.get("z_score", 0.0),
            "status":          narrative_info.get("status", "NO_DATA"),
            "is_burst":        narrative_info.get("is_burst", False),
            "normalized_freq": narrative_info.get("normalized_freq", 0.0),
            "baseline_mean":   narrative_info.get("baseline_mean", 0.0),
            "baseline_std":    narrative_info.get("baseline_std", 0.0),
            "keyword_hits":    narrative_info.get("keyword_hits", 0),
            "article_count":   narrative_info.get("article_count", 0),
        },
        "isr_hotspot": {
            "count":    isr_info.get("count", 0),
            "is_surge": isr_info.get("is_surge", False),
            "hotspots": isr_info.get("hotspots", []),
        },
        "ais_maritime": {
            "dark_gaps":   ais_gaps[:5],
            "stationary":  ais_stat[:5],
            "has_anomaly": bool(ais_gaps or ais_stat),
        },
        "blockade_index": {
            "value":       blockade_idx,
            "ddos_spike":  core_spike_v,
            "is_degraded": is_degraded,
            "interpretation": (
                "INFRASTRUCTURE_NEUTRALIZATION" if blockade_idx >= 7.0 else
                "SEVERE_DISRUPTION"             if blockade_idx >= 4.0 else
                "POLITICAL_NOISE"               if blockade_idx >= 1.5 else
                "NORMAL"
            ),
        },
    })


@bp.route("/api/salute_report", methods=["GET"])
@_analytics_read
def api_salute_report():
    """
    Generate the current threat situation as a SALUTE format (Size/Activity/Location/Unit/Time/Equipment)
    contact report. Activates the analyst's trained cognitive mode.
    Supports ?lang=en (default) or ?lang=ja.
    """
    lang = request.args.get('lang', 'en')
    ja   = (lang == 'ja')

    strat = st.global_cache.get("strategic", {})
    p8    = strat.get("analytics", {})
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    dtg = now_ts.strftime("%d%H%MZ %b %Y").upper()
    threat_level = strat.get("threat_level", 5)
    core   = strat.get("core_theater", "UNKNOWN")
    bd     = strat.get("threat_breakdown", {})
    adv_raw = strat.get("adversary_strikes", [])
    adv     = list(dict.fromkeys(a.get("actor", str(a)) if isinstance(a, dict) else str(a) for a in adv_raw))
    # Phase 5: only `len(corr)` is used here (count of correlation pairs).
    # Both raw `correlations` and `correlations_idf_l3` share the same key set
    # so the count is identical — read the IDF surface to drop the raw dep.
    corr   = strat.get("correlations_idf_l3", {})
    isr    = p8.get("isr", {})
    ais    = p8.get("ais", {})
    narr   = p8.get("narrative", {})
    bi     = p8.get("blockade_index", 0.0)
    seq    = p8.get("sequence_status", "NO_EVENTS")

    # SIZE: actors and scale involved
    size_parts = []
    if adv:
        size_parts.append(f"{'敵対国家' if ja else 'ADVERSARY STATES'}: {', '.join(adv)}")
    if corr:
        size_parts.append(f"{'連携シアター' if ja else 'CORRELATED THEATERS'}: {len(corr)}{'か国' if ja else ''}")
    if isr.get("count", 0):
        size_parts.append(f"{'ISR機' if ja else 'ISR AIRCRAFT'}: {isr['count']}{'機' if ja else ''}")
    size = "; ".join(size_parts) if size_parts else ("不明 — 評価進行中" if ja else "UNKNOWN — ASSESSMENT IN PROGRESS")

    # ACTIVITY: observed activity
    acts = []
    if bd.get("core_spike_val", 0) > 2:
        layer = ("L7アプリケーション層" if ja else "L7 APPLICATION") if bd.get("core_shifted") else ("L3ボリューメトリック" if ja else "L3 VOLUMETRIC")
        acts.append(f"DDoS {bd['core_spike_val']:.1f}{'×スパイク（' if ja else 'x SPIKE ('}{layer}{'）' if ja else ')'}")
    if bd.get("is_coordinated"):
        acts.append("協調型多正面活動" if ja else "COORDINATED MULTI-FRONT ACTIVITY")
    if isr.get("is_surge"):
        acts.append("ISRサージ確認" if ja else "ISR SURGE CONFIRMED")
    if ais.get("dark_gaps", 0):
        acts.append(f"{'チョークポイントでAISダークギャップ×' if ja else 'AIS DARK GAP x'}{ais['dark_gaps']}{'件' if ja else ' AT CHOKEPOINTS'}")
    if narr.get("is_burst"):
        acts.append(f"{'ナラティブバースト Z=' if ja else 'NARRATIVE BURST Z='}{narr.get('z_score',0):.1f}")
    if p8.get("is_ambush"):
        acts.append(f"{'待伏パターン（Z=' if ja else 'AMBUSH PATTERN (Z='}{p8.get('ambush_z_score',0):.1f}{'）' if ja else ')'}")
    activity = "; ".join(acts) if acts else ("通常 — 特記すべき活動なし" if ja else "ROUTINE — NO SIGNIFICANT ACTIVITY")

    # LOCATION: primary threat location
    degraded = strat.get("degraded_theaters", [])
    loc_parts = [f"{'主要' if ja else 'PRIMARY'}: {core}"]
    if degraded:
        loc_parts.append(f"{'劣化中' if ja else 'DEGRADED'}: {', '.join(degraded)}")
    location = " / ".join(loc_parts)

    # UNIT: attribution assessment
    if adv and bd.get("major_adversary"):
        unit = f"{'国家帰属確認 — ' if ja else 'STATE-ATTRIBUTED — '}{', '.join(adv)} {'国家ASN一致' if ja else 'STATE ASN CONFIRMED'}"
    elif bd.get("is_coordinated"):
        unit = "協調的 — 国家C2の可能性（帰属不明）" if ja else "COORDINATED — PROBABLE STATE C2 (UNKNOWN ATTRIBUTION)"
    else:
        unit = "不明 — 帰属評価中" if ja else "UNKNOWN — ATTRIBUTION ASSESSMENT PENDING"

    # EQUIPMENT: attack vectors and tools used
    equip_parts = []
    if bd.get("core_shifted"):
        equip_parts.append("L7 HTTPフラッド（意思決定麻痺型）" if ja else "L7 HTTP FLOOD (DECISION-PARALYSIS TYPE)")
    elif bd.get("core_spike_val", 0) > 2:
        equip_parts.append("L3帯域幅枯渇（盲目化型）" if ja else "L3 BANDWIDTH EXHAUSTION (BLINDING TYPE)")
    if bd.get("tl1_hard"):
        equip_parts.append("インフラ無力化能力" if ja else "INFRASTRUCTURE NEUTRALIZATION CAPABILITY")
    if isr.get("is_surge"):
        equip_parts.append("ISRプラットフォーム展開" if ja else "ISR PLATFORM DEPLOYMENT")
    if ais.get("dark_gaps", 0):
        equip_parts.append("秘密海上要素" if ja else "COVERT MARITIME ELEMENT")
    equip = "; ".join(equip_parts) if equip_parts else ("標準的サイバーツール" if ja else "STANDARD CYBER TOOLS")

    # ASSESSMENT — full narrative assessment paragraph
    sig_map = (
        {1: "危機的", 2: "高度", 3: "重大", 4: "中程度", 5: "通常"} if ja else
        {1: "CRITICAL", 2: "HIGH", 3: "SIGNIFICANT", 4: "MODERATE", 5: "ROUTINE"}
    )
    significance = sig_map.get(threat_level, "不明" if ja else "UNKNOWN")

    bi_interp_map = (
        {7.0: "インフラ無力化", 4.0: "重度障害", 1.5: "政治的ノイズ"} if ja else
        {7.0: "INFRASTRUCTURE NEUTRALIZATION", 4.0: "SEVERE DISRUPTION", 1.5: "POLITICAL NOISE"}
    )
    bi_interp = next((v for k, v in sorted(bi_interp_map.items(), reverse=True) if bi >= k), ("通常" if ja else "NORMAL"))

    conv_level = strat.get("convergence_level", "NONE")
    conv_map = (
        {"FULL_CONVERGENCE": "完全収束（3ドメイン活性化）", "DUAL_DOMAIN": "2ドメイン収束", "SINGLE_DOMAIN": "単一ドメイン活動", "NONE": "収束なし"} if ja else
        {"FULL_CONVERGENCE": "FULL CONVERGENCE (3 domains active)", "DUAL_DOMAIN": "DUAL DOMAIN convergence", "SINGLE_DOMAIN": "SINGLE DOMAIN activity", "NONE": "NO CONVERGENCE"}
    )
    conv_text = conv_map.get(conv_level, conv_level)

    # Domain scores for assessment
    domains = strat.get("domains", {})
    domain_parts = []
    for d_key, d_label in [("cyber", "Cyber" if not ja else "サイバー"), ("physical", "Physical" if not ja else "物理"), ("info", "Info" if not ja else "情報")]:
        d_info = domains.get(d_key, {})
        if d_info.get("score", 0) > 0:
            domain_parts.append(f"{d_label}: {d_info['score']}pt")

    # Velocity and trend
    vel = p8.get("velocity", 0.0)
    vel_label = ("急上昇" if ja else "RAPIDLY ESCALATING") if vel > 1.0 else \
                ("上昇中" if ja else "ESCALATING") if vel > 0.3 else \
                ("安定" if ja else "STABLE") if vel > -0.3 else \
                ("低下中" if ja else "DE-ESCALATING")

    # Build assessment paragraph
    assess_parts = []
    if ja:
        assess_parts.append(f"脅威レベル{threat_level}（{significance}）。")
        assess_parts.append(f"収束状態: {conv_text}。")
        if domain_parts:
            assess_parts.append(f"ドメインスコア: {', '.join(domain_parts)}。")
        assess_parts.append(f"脅威速度: {vel_label}（{vel:+.2f}/時間）。")
        if bi >= 1.5:
            assess_parts.append(f"封鎖指数: {bi:.1f}/10（{bi_interp}）。")
        if seq not in ("NO_EVENTS", "INSUFFICIENT_CHAIN (0/4)"):
            assess_parts.append(f"シーケンスチェーン: {seq}。")
    else:
        assess_parts.append(f"THREAT LEVEL {threat_level} ({significance}).")
        assess_parts.append(f"Convergence: {conv_text}.")
        if domain_parts:
            assess_parts.append(f"Domain scores: {', '.join(domain_parts)}.")
        assess_parts.append(f"Threat velocity: {vel_label} ({vel:+.2f}/hr).")
        if bi >= 1.5:
            assess_parts.append(f"Blockade Index: {bi:.1f}/10 ({bi_interp}).")
        if seq not in ("NO_EVENTS", "INSUFFICIENT_CHAIN (0/4)"):
            assess_parts.append(f"Sequence chain: {seq}.")

    # Noise filters active
    noise_filters = strat.get("noise_filters_applied", [])
    if noise_filters:
        nf_text = "適用ノイズフィルター" if ja else "Noise filters applied"
        assess_parts.append(f"{nf_text}: {', '.join(noise_filters)}.")

    assessment_text = " ".join(assess_parts)

    no_chain_text = "活動中のシーケンスチェーンなし" if ja else "NO ACTIVE SEQUENCE CHAIN"
    report = {
        "dtg":          dtg,
        "size":         size,
        "activity":     activity,
        "location":     location,
        "unit":         unit,
        "time":         dtg,
        "equipment":    equip,
        "assessment":   assessment_text,
        "threat_level": threat_level,
        "convergence":  conv_text,
        "velocity":     vel_label,
        "blockade_interpretation": bi_interp,
        "blockade_index": bi,
        "sequence_status": seq,
        "cross_ref": (
            f"{'シーケンスチェーン' if ja else 'SEQ CHAIN'}: {seq}"
            if seq not in ("NO_EVENTS", "INSUFFICIENT_CHAIN (0/4)") else no_chain_text
        ),
    }
    return jsonify({"ts": now_ts.isoformat(), "report": report})


@bp.route("/api/weather_brief", methods=["GET"])
@_analytics_read
def api_weather_brief():
    """
    Convert current sensor data to an "Operational Weather Brief" format and return it.
    Uses meteorological terminology to intuitively represent the threat environment.
    Supports ?lang=en (default) or ?lang=ja.
    """
    lang = request.args.get('lang', 'en')
    ja   = (lang == 'ja')

    strat = st.global_cache.get("strategic", {})
    p8    = strat.get("analytics", {})
    bd    = strat.get("threat_breakdown", {})
    isr   = p8.get("isr", {})
    ais   = p8.get("ais", {})
    narr  = p8.get("narrative", {})
    bi    = p8.get("blockade_index", 0.0)
    vel   = p8.get("velocity", 0.0)
    is_ambush = p8.get("is_ambush", False)

    # CYBER ATMOSPHERE
    spike = bd.get("core_spike_val", 0.0)
    if is_ambush:
        cyber_state = "急速強化中 — 指数的上昇" if ja else "RAPID INTENSIFICATION"
        cyber_desc  = (f"指数的エスカレーションを検出。眼壁形成中。気圧降下速度 {vel*900:.2f}pt/サイクル。" if ja else
                       f"Exponential escalation detected. Eye-wall forming. Barometric pressure dropping at {vel*900:.2f}pt/cycle.")
    elif spike > 6:
        cyber_state = "大規模サイバー嵐" if ja else "MAJOR STORM"
        cyber_desc  = (f"カテゴリ{min(int(spike/2),5)}サイバー嵐。{spike:.1f}×ベースライン。主ベクター: L{'7' if bd.get('core_shifted') else '3'}。" if ja else
                       f"Category {min(int(spike/2),5)} cyber storm. {spike:.1f}x baseline. L{'7' if bd.get('core_shifted') else '3'} dominant vector.")
    elif spike > 3:
        cyber_state = "嵐の前線活発化" if ja else "ACTIVE STORM FRONT"
        cyber_desc  = (f"重大な擾乱を検出。{spike:.1f}×ベースライン。状況悪化が予測される。" if ja else
                       f"Significant disturbance. {spike:.1f}x baseline. Deepening conditions expected.")
    elif spike > 1:
        cyber_state = "うねり上昇中" if ja else "ELEVATED SWELL"
        cyber_desc  = (f"海面不穏。{spike:.1f}×ベースライン。前線発達の可能性あり、要監視。" if ja else
                       f"Choppy seas. {spike:.1f}x baseline. Monitor for front development.")
    else:
        cyber_state = "平穏 — 異常なし" if ja else "CLEAR"
        cyber_desc  = "穏やかな状況。バックグラウンドノイズのみ。視界良好。" if ja else "Calm conditions. Background noise only. Visibility good."

    # MARITIME ENVIRONMENT (AIS)
    if ais.get("dark_gaps", 0) > 2:
        mar_state = "視界ゼロ — 濃霧" if ja else "ZERO VISIBILITY — DENSE FOG"
        mar_desc  = (f"{ais['dark_gaps']}隻が重要チョークポイント付近で消息不明。電波沈黙は秘密作戦態勢を示す。" if ja else
                     f"{ais['dark_gaps']} vessels gone dark near critical chokepoints. Radio silence indicates covert posture.")
    elif ais.get("dark_gaps", 0) > 0:
        mar_state = "視界低下 — 断続的霧" if ja else "REDUCED VISIBILITY — PATCHY FOG"
        mar_desc  = (f"AISダークギャップ {ais['dark_gaps']}件を検出。継続的な監視を推奨。" if ja else
                     f"{ais['dark_gaps']} AIS Dark Gap(s) detected. Recommend continuous monitoring.")
    elif ais.get("stationary", 0) > 0:
        mar_state = "制限水域 — 障害物検出" if ja else "RESTRICTED WATERS — OBSTACLE"
        mar_desc  = (f"非商業船舶 {ais['stationary']}隻がチョークポイント付近に停泊中。異常な挙動。" if ja else
                     f"{ais['stationary']} non-commercial vessel(s) anchored near chokepoint. Anomalous.")
    else:
        mar_state = "通過良好 — 異常なし" if ja else "CLEAR PASSAGE"
        mar_desc  = "通常の海上交通。AIS異常なし。" if ja else "Normal maritime traffic. No AIS anomalies detected."

    # INFORMATION ENVIRONMENT (Narrative)
    nz = narr.get("z_score", 0.0)
    ns = narr.get("status", "NORMAL")
    if ns == "CRITICAL_BURST":
        info_state = "情報嵐 — ハリケーン級" if ja else "INFORMATION STORM — HURRICANE FORCE"
        info_desc  = (f"Z={nz:.1f}。戦術キーワードが飽和状態。プロパガンダ機構が過活動。作戦前情報準備を検出。" if ja else
                      f"Z={nz:.1f}. Tactical keyword saturation. Propaganda machine in overdrive. Pre-operation information preparation detected.")
    elif ns == "BURST":
        info_state = "上昇気圧 — 嵐発達中" if ja else "ELEVATED PRESSURE — BUILDING STORM"
        info_desc  = (f"Z={nz:.1f}。国営メディアで異常なキーワード急増。嵐の前線接近中。" if ja else
                      f"Z={nz:.1f}. Unusual keyword spike in state media. Storm front approaching.")
    else:
        info_state = "定常状態 — 通常範囲内" if ja else "STEADY STATE"
        info_desc  = (f"Z={nz:.1f}。バックグラウンドプロパガンダは正常範囲内。重大な前線なし。" if ja else
                      f"Z={nz:.1f}. Background propaganda within normal parameters. No significant front detected.")

    # AIR PICTURE (ISR)
    if isr.get("is_surge"):
        air_state = "活発 — ISR全面展開" if ja else "ACTIVE — FULL ISR DEPLOYMENT"
        air_desc  = (f"戦略的ホットスポットでISR機 {isr.get('count',0)}機を確認。打撃前偵察態勢。" if ja else
                     f"{isr.get('count',0)} ISR aircraft confirmed at strategic hotspot(s). Pre-strike reconnaissance posture.")
    elif isr.get("count", 0) > 0:
        air_state = "観測 — 通常ISRパターン" if ja else "OBSERVED — ROUTINE ISR PATTERN"
        air_desc  = (f"ISR機 {isr.get('count',0)}機を観測。通常の哨戒頻度。" if ja else
                     f"{isr.get('count',0)} ISR aircraft observed. Normal patrol frequency.")
    else:
        air_state = "晴天 — ISR集中なし" if ja else "CLEAR SKIES"
        air_desc  = "監視ホットスポットでISR集中を検出せず。" if ja else "No ISR concentration detected at monitored hotspots."

    # BLOCKADE (Infrastructure pressure)
    if bi >= 7:
        infra_state = "壊滅的 — インフラ崩壊" if ja else "CATASTROPHIC — INFRASTRUCTURE COLLAPSE"
        infra_desc  = (f"指数 {bi:.1f}。DDoSとBGP撤退の複合。ブラックアウト状態。侵攻前兆シグネチャ。" if ja else
                       f"Index {bi:.1f}. Combined DDoS and BGP withdrawal. Blackout conditions. Invasion precursor signature.")
    elif bi >= 4:
        infra_state = "深刻 — 持続的圧力" if ja else "SEVERE — SUSTAINED PRESSURE"
        infra_desc  = (f"指数 {bi:.1f}。サイバー活動に並行した重大なインフラ劣化。" if ja else
                       f"Index {bi:.1f}. Significant infrastructure degradation concurrent with cyber activity.")
    elif bi >= 1.5:
        infra_state = "上昇 — 政治的ノイズレベル" if ja else "ELEVATED — POLITICAL NOISE LEVEL"
        infra_desc  = (f"指数 {bi:.1f}。インフラへの確認済み影響なし。シグナリング作戦の可能性あり。" if ja else
                       f"Index {bi:.1f}. Cyber activity without confirmed infrastructure impact. Signaling operation likely.")
    else:
        infra_state = "正常 — 安定" if ja else "NOMINAL"
        infra_desc  = (f"指数 {bi:.1f}。インフラ安定。障害なし。" if ja else
                       f"Index {bi:.1f}. Infrastructure stable. No disruption confirmed.")

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "brief": {
            "cyber":    {"state": cyber_state,  "detail": cyber_desc},
            "maritime": {"state": mar_state,    "detail": mar_desc},
            "info":     {"state": info_state,   "detail": info_desc},
            "air":      {"state": air_state,    "detail": air_desc},
            "infra":    {"state": infra_state,  "detail": infra_desc},
        }
    })


@bp.route("/api/ip_check", methods=["GET"])
@_analytics_read
def api_ip_check():
    """Look up IP address noise/classification info via GreyNoise Community API.

    Query params:
        ip (str, required): IPv4 address to investigate

    Response:
        {
          "ip":             "1.2.3.4",
          "noise":          false,         // true = internet background noise (mass scanners etc.)
          "riot":           false,         // true = legitimate infrastructure (Google, Cloudflare etc.)
          "classification": "malicious",   // malicious / benign / unknown
          "name":           "Mirai Botnet",
          "last_seen":      "2026-03-13",
          "message":        "...",
          "cached":         false,         // true = cache hit (no API quota consumed)
          "fetched_at":     1234567890.0,
          "daily_remaining": 47,           // remaining requests today
          "error":          null
        }

    Note:
        Community API: 50 req/day. Same IP cached for 24h without consuming quota.
        Uses Community endpoint even with Enterprise key (separate from GNQL Stats).
    """
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required. Example: /api/ip_check?ip=1.2.3.4"}), 400

    gn_sensor = _routes.registry.get("greynoise")
    if not gn_sensor:
        return jsonify({"error": "GreyNoiseSensor is not initialized"}), 503

    result = gn_sensor.lookup_community_ip(ip)

    if result.get("error") and "limit" not in result["error"] and "Invalid" not in result["error"]:
        return jsonify(result), 502
    return jsonify(result)



# ─────────────────────────────────────────────────────────────────────────────
# Background cleanup thread
# Removes old entries from global caches every hour to prevent memory leaks in long-running processes.

@bp.route("/api/score_breakdown", methods=["GET"])
@_analytics_read
def api_score_breakdown():
    """
    Per-sensor score breakdown for the current threat assessment.
    Restructures rationale_matrix from the global cache by domain,
    sorted by score descending within each domain.
    """
    with _global_cache_lock:
        cache = dict(st.global_cache) if st.global_cache else None
    if not cache or not cache.get("strategic"):
        return jsonify({"error": "No data available"}), 503

    strat = cache["strategic"]
    rationale = strat.get("rationale_matrix", [])
    domains_data = strat.get("domains", {})

    breakdown: dict = {"cyber": [], "physical": [], "info": []}
    for entry in rationale:
        d = entry.get("domain")
        if d not in breakdown:
            continue
        breakdown[d].append({
            "sensor":         entry.get("sensor"),
            "status":         entry.get("status"),
            "score":          entry.get("score", 0),
            "value":          entry.get("value", ""),
            "fired_reason":   entry.get("fired_reason"),
            "suppressed":     entry.get("suppressed", False),
            "suppress_reason": entry.get("suppress_reason"),
        })

    # Sort contributors by score descending within each domain
    for d in breakdown:
        breakdown[d].sort(key=lambda x: -(x.get("score") or 0))

    return jsonify({
        "ts":           datetime.datetime.now().isoformat(),
        "theater":      strat.get("core_theater"),
        # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
        "country":      strat.get("core_theater"),
        "threat_level": strat.get("threat_level", 5),
        "domains": {
            d: {
                "score":        domains_data.get(d, {}).get("score", 0),
                "status":       domains_data.get(d, {}).get("status", "NORMAL"),
                "contributors": breakdown.get(d, []),
            }
            for d in ("cyber", "physical", "info")
        },
    })


# ─────────────────────────────────────────────────────────────────────────────
# ── What-If Simulation Endpoint
# ─────────────────────────────────────────────────────────────────────────────

# Known sensors with their domain, display label, and max score
WHATIF_SENSOR_CATALOG = [
    {"sensor": "cf_spike_core",      "domain": "cyber",    "label": "Cloudflare DDoS Spike",        "max_score": 3},
    {"sensor": "cf_botnet_overlap",  "domain": "cyber",    "label": "Botnet Overlap >30%",          "max_score": 1},
    {"sensor": "cf_vector_shift",    "domain": "cyber",    "label": "L7 Vector Shift",              "max_score": 1},
    {"sensor": "cf_adversary_strike","domain": "cyber",    "label": "Adversary State Strike",       "max_score": 2},
    {"sensor": "cf_coordinated",     "domain": "cyber",    "label": "Coordinated Multi-Theater",    "max_score": 1},
    {"sensor": "ripe_bgp",           "domain": "cyber",    "label": "RIPE BGP Anomaly",             "max_score": 1},
    {"sensor": "threatfox",          "domain": "cyber",    "label": "ThreatFox APT IoC",            "max_score": 1},
    {"sensor": "ddos_acceleration",  "domain": "cyber",    "label": "DDoS Ambush Pattern",          "max_score": 2},
    {"sensor": "greynoise",          "domain": "cyber",    "label": "GreyNoise Noise Suppressor",   "max_score": 0, "is_suppressor": True},
    {"sensor": "ioda_bgp",           "domain": "physical", "label": "IODA BGP Outage",              "max_score": 1},
    {"sensor": "opensky",            "domain": "physical", "label": "Airspace Anomaly/Closure",     "max_score": 3},
    {"sensor": "nasa_firms",         "domain": "physical", "label": "NASA FIRMS Thermal Anomaly",   "max_score": 3},
    {"sensor": "isr_hotspot",        "domain": "physical", "label": "ISR Surge",                    "max_score": 2},
    {"sensor": "ais_maritime",       "domain": "physical", "label": "AIS Dark Gap / Stationary",    "max_score": 1},
    {"sensor": "check_host",         "domain": "physical", "label": "Check-Host Infra Survival",    "max_score": 3},
    {"sensor": "openweather",        "domain": "physical", "label": "Weather (Noise Filter)",       "max_score": 0, "is_suppressor": True},
    {"sensor": "gdelt",              "domain": "info",     "label": "GDELT Media Tone",             "max_score": 1},
    {"sensor": "rss_narrative",      "domain": "info",     "label": "RSS Narrative Burst",          "max_score": 2},
    {"sensor": "telegram_mirror",    "domain": "info",     "label": "Telegram Mirror SIGINT",       "max_score": 2},
    {"sensor": "maskirovka_flag",    "domain": "info",     "label": "Maskirovka Detection",         "max_score": 2},
]


@bp.route("/api/whatif/catalog", methods=["GET"])
@_analytics_read
def whatif_catalog():
    """Return the sensor catalog for the What-If simulation UI."""
    return jsonify({"sensors": WHATIF_SENSOR_CATALOG})


@bp.route("/api/whatif/simulate", methods=["POST"])
@_analytics_read
def whatif_simulate():
    """
    Run a What-If simulation with user-injected virtual sensor events.

    Request body (JSON):
    {
      "events": [
        {"sensor": "cf_spike_core", "score": 3, "suppressed": false},
        {"sensor": "ioda_bgp",      "score": 1, "suppressed": false},
        {"sensor": "rss_narrative",  "score": 2, "suppressed": false}
      ],
      "tl1_hard": false,        // optional: override core_degraded flag
      "sequence_bonus": 0,      // optional: inject sequence bonus
      "temporal_bonus": 0       // optional: inject temporal coherence bonus
    }

    Returns: simulated threat level, domain scores, convergence, and full breakdown.
    """
    body = request.get_json(force=True, silent=True) or {}
    events = body.get("events", [])
    tl1_hard_override = body.get("tl1_hard", False)
    seq_bonus = int(body.get("sequence_bonus", 0))
    temporal_bonus = int(body.get("temporal_bonus", 0))

    # Build a sensor lookup from the catalog
    catalog_map = {s["sensor"]: s for s in WHATIF_SENSOR_CATALOG}

    # Build rationale entries from the injected events
    rationale: list[RationaleEntry] = []
    for evt in events:
        sensor_name = evt.get("sensor", "")
        cat = catalog_map.get(sensor_name)
        if not cat:
            continue
        score = min(int(evt.get("score", 0)), cat["max_score"])
        is_suppressed = bool(evt.get("suppressed", False))
        is_suppressor = cat.get("is_suppressor", False)
        fired = score > 0 and not is_suppressed

        rationale.append(RationaleEntry(
            sensor=sensor_name,
            domain=cat["domain"],
            status="FIRED" if fired else ("SUPPRESSED" if is_suppressed else "OK"),
            value=f"[What-If] score={score}",
            score=score if not is_suppressed else 0,
            fired_reason=f"What-If injection: {cat['label']}" if fired else None,
            suppressed=is_suppressed or is_suppressor,
            suppress_reason="What-If: manually suppressed" if is_suppressed else (
                "Noise suppressor sensor" if is_suppressor else None),
        ))

    engine = _routes.engine
    domain_scores = engine.compute_domain_scores(rationale)
    total_score = sum(e.score for e in rationale if e.status == "FIRED" and not e.suppressed)
    convergence_score = engine.compute_convergence_score(domain_scores)
    score_with_bonus, conv_bonus, convergence_level = engine.apply_convergence_bonus(total_score, domain_scores)
    score_with_bonus += seq_bonus + temporal_bonus
    score_with_bonus = min(score_with_bonus, 15)
    active_domains = sum(1 for s in domain_scores.values() if s > 0)
    # Derive TL using the canonical scoring function (single source of truth
    # with /api/threat_data). The legacy tl1_hard flag is preserved as an
    # explicit TL1 override when score >= 9 but physical_score < 3.
    _active_domain_list = [d for d, s in domain_scores.items() if s > 0]
    _physical_score = domain_scores.get("physical", 0)
    threat_level = derive_tl(score_with_bonus, _active_domain_list, _physical_score)
    if tl1_hard_override and score_with_bonus >= 9 and threat_level > 1:
        threat_level = 1

    system_note = engine.build_system_note(threat_level, domain_scores, convergence_level, rationale, [])

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "simulation": True,
        "threat_level": threat_level,
        "total_score": total_score,
        "score_with_bonus": score_with_bonus,
        "convergence_score": round(convergence_score, 2),
        "convergence_level": convergence_level,
        "convergence_bonus": conv_bonus,
        "sequence_bonus": seq_bonus,
        "temporal_bonus": temporal_bonus,
        "tl1_hard": tl1_hard_override,
        "active_domains": active_domains,
        "domain_scores": {
            d: {
                "score": domain_scores.get(d, 0),
                "weight": engine.DOMAIN_WEIGHTS.get(d, 0),
                "weighted": round(min(domain_scores.get(d, 0), 10) * engine.DOMAIN_WEIGHTS.get(d, 0), 2),
                "status": (
                    "CRITICAL" if domain_scores.get(d, 0) >= 6 else
                    "ELEVATED" if domain_scores.get(d, 0) >= 3 else
                    "WATCH"    if domain_scores.get(d, 0) >= 1 else "NORMAL"
                ),
            }
            for d in ("cyber", "physical", "info")
        },
        "rationale": [e.to_dict() for e in rationale],
        "system_note": system_note,
    })


# ─────────────────────────────────────────────────────────────────────────────
# ── SPOF (Single Point of Failure) Analysis Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/api/spof_analysis", methods=["GET"])
@_analytics_read
def spof_analysis():
    """
    Compute sensor SPOF (single point of failure) analysis.
    For each active sensor, estimates the confidence degradation
    if that sensor were to go offline.

    Returns per-sensor impact data and overall domain health.
    """
    with _global_cache_lock:
        cache = dict(st.global_cache) if st.global_cache else None
    if not cache or not cache.get("strategic"):
        return jsonify({"error": "No data available"}), 503

    strat = cache["strategic"]
    rationale = strat.get("rationale_matrix", [])
    domains_data = strat.get("domains", {})
    current_tl = strat.get("threat_level", 5)

    engine = _routes.engine

    # Compute baseline domain scores from current rationale
    baseline_entries = [
        RationaleEntry(**{k: e[k] for k in
                          ("sensor", "domain", "status", "value", "score",
                           "fired_reason", "suppressed", "suppress_reason")})
        for e in rationale
    ]
    baseline_domain_scores = engine.compute_domain_scores(baseline_entries)
    baseline_total = sum(
        e.score for e in baseline_entries
        if e.status == "FIRED" and not e.suppressed
    )

    # Collect sensor health info
    sensor_health = {}
    for s in _routes.registry._sensors.values():
        sensor_health[s.name] = {
            "enabled": s.enabled,
            "health": s.health,
            "domain": s.domain,
            "last_error": s._last_error,
            "cache_age_sec": round(time.time() - s._cache_time) if s._cache_time else None,
        }

    # For each fired sensor, compute what happens if it goes offline
    spof_entries = []
    fired_sensors = [
        e for e in rationale
        if e.get("status") == "FIRED" and not e.get("suppressed", False) and e.get("score", 0) > 0
    ]

    for entry in fired_sensors:
        sensor_name = entry["sensor"]
        sensor_domain = entry["domain"]
        sensor_score = entry.get("score", 0)

        # Simulate removal: build rationale without this sensor
        sim_entries = [
            RationaleEntry(**{k: e[k] for k in
                              ("sensor", "domain", "status", "value", "score",
                               "fired_reason", "suppressed", "suppress_reason")})
            for e in rationale if e["sensor"] != sensor_name
        ]
        sim_domain_scores = engine.compute_domain_scores(sim_entries)
        sim_total = sum(
            e.score for e in sim_entries
            if e.status == "FIRED" and not e.suppressed
        )
        sim_score_with_bonus, sim_conv_bonus, sim_conv_level = engine.apply_convergence_bonus(sim_total, sim_domain_scores)
        sim_active = sum(1 for s in sim_domain_scores.values() if s > 0)

        # Check if removing this sensor causes domain deactivation
        domain_lost = (
            baseline_domain_scores.get(sensor_domain, 0) > 0 and
            sim_domain_scores.get(sensor_domain, 0) == 0
        )
        # Check if convergence level drops
        baseline_conv = engine.compute_convergence_level(baseline_domain_scores)
        sim_conv = engine.compute_convergence_level(sim_domain_scores)
        convergence_downgrade = baseline_conv != sim_conv

        score_impact = baseline_total - sim_total
        health_info = sensor_health.get(sensor_name, {})

        spof_entries.append({
            "sensor": sensor_name,
            "domain": sensor_domain,
            "current_score": sensor_score,
            "score_impact": score_impact,
            "domain_lost": domain_lost,
            "convergence_downgrade": convergence_downgrade,
            "convergence_from": baseline_conv,
            "convergence_to": sim_conv,
            "health": health_info.get("health", "unknown"),
            "enabled": health_info.get("enabled", True),
            "last_error": health_info.get("last_error"),
            "cache_age_sec": health_info.get("cache_age_sec"),
            "has_fallback": False,
            "criticality": (
                "CRITICAL" if domain_lost or convergence_downgrade else
                "HIGH"     if score_impact >= 3 else
                "MEDIUM"   if score_impact >= 2 else
                "LOW"
            ),
        })

    # Sort by criticality: CRITICAL > HIGH > MEDIUM > LOW
    crit_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    spof_entries.sort(key=lambda x: (crit_order.get(x["criticality"], 9), -x["score_impact"]))

    # Domain health summary
    domain_summary = {}
    for d in ("cyber", "physical", "info"):
        d_sensors = [s for s in spof_entries if s["domain"] == d]
        d_score = baseline_domain_scores.get(d, 0)
        domain_summary[d] = {
            "score": d_score,
            "sensor_count": len([e for e in rationale if e.get("domain") == d and e.get("status") != "DISABLED"]),
            "fired_count": len([e for e in rationale if e.get("domain") == d and e.get("status") == "FIRED" and not e.get("suppressed")]),
            "critical_spofs": len([s for s in d_sensors if s["criticality"] == "CRITICAL"]),
            "has_redundancy": len([e for e in rationale if e.get("domain") == d and e.get("status") == "FIRED" and not e.get("suppressed")]) >= 2,
        }

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "current_threat_level": current_tl,
        "baseline_total_score": baseline_total,
        "baseline_convergence": engine.compute_convergence_level(baseline_domain_scores),
        "spof_entries": spof_entries,
        "domain_summary": domain_summary,
    })


# ─────────────────────────────────────────────────────────────────────────────
# ── Phase 2: Adaptive Z-score Status API
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/api/adaptive_zscore_status", methods=["GET"])
@_analytics_read
def adaptive_zscore_status():
    """
    Return per-sensor/per-theater adaptive Z-score statistics.
    Shows sample counts, running mean/std, and whether adaptive mode is active.
    """
    from radar.config import ADAPTIVE_ZSCORE_ENABLED, ADAPTIVE_ZSCORE_MIN_SAMPLES
    stats = _db.zscore_stats_all()
    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "enabled": ADAPTIVE_ZSCORE_ENABLED,
        "min_samples": ADAPTIVE_ZSCORE_MIN_SAMPLES,
        "sensors": [
            {
                **s,
                "mode": "adaptive" if s["sample_count"] >= ADAPTIVE_ZSCORE_MIN_SAMPLES else "warmup",
            }
            for s in stats
        ],
    })


_VALID_SOURCES = ("all", "analyst", "shadow_sampler")


def _parse_source(raw: str | None) -> str | None:
    """Map ?source= query value to focus_switch_log filter. 'all' (or
    missing/invalid) returns None meaning no filter; 'analyst' /
    'shadow_sampler' return the literal source value."""
    if not raw:
        return None
    raw = raw.strip().lower()
    if raw not in _VALID_SOURCES:
        return None
    return None if raw == "all" else raw


@bp.route("/api/analytics/focus_switches", methods=["GET"])
@_analytics_read
def api_focus_switch_stats():
    """C-medium migration metric: focus switch miss rate (Section 9.3.1).

    Query params:
      - days: lookback window (default 28)
      - source: 'all' (default), 'analyst', or 'shadow_sampler' (ADR-025)
    """
    days = _safe_int(request.args.get("days", "28"), 28, min_val=1, max_val=365)
    source = _parse_source(request.args.get("source"))
    return jsonify(_db.focus_switch_stats(days=days, source=source))


@bp.route("/api/analytics/clite_evaluation", methods=["GET"])
@_analytics_read
def api_clite_evaluation():
    """Comprehensive C-lite vs C-medium evaluation dashboard.

    Returns miss rate, delta distribution, per-scenario breakdown, and a
    recommendation (LITE_SUFFICIENT / CONSIDER_C_MEDIUM / INSUFFICIENT_DATA).

    Query params:
      - days: lookback window (default 28)
      - source: 'all' (default), 'analyst', or 'shadow_sampler' (ADR-025)
    """
    days = _safe_int(request.args.get("days", "28"), 28, min_val=1, max_val=365)
    source = _parse_source(request.args.get("source"))
    return jsonify(_db.focus_switch_detailed(days=days, source=source))


@bp.route("/api/analytics/cmedium_recommendation", methods=["GET"])
@_analytics_read
def api_cmedium_recommendation():
    """Per-scenario C-medium migration recommendation (scenario-refactor §9.3.1).

    Honors C_MEDIUM_* config knobs:
      - WINDOW_DAYS: observation window
      - DELTA_MISS: |full_score - lite_score| above which an analyst switch counts as a miss
      - DELTA_MISS_SHADOW: same threshold applied to shadow_sampler rows (ADR-025)
      - MISS_THRESHOLD: miss_rate above which CONSIDER_C_MEDIUM fires
      - MIN_SWITCHES: minimum switch count before any recommendation is meaningful

    Query params:
      - days: lookback window (default = C_MEDIUM_WINDOW_DAYS)
      - source: 'all' (default), 'analyst', or 'shadow_sampler'
    """
    from radar.scenarios import scenario_store
    days = _safe_int(
        request.args.get("days", str(C_MEDIUM_WINDOW_DAYS)),
        C_MEDIUM_WINDOW_DAYS, min_val=1, max_val=365,
    )
    source = _parse_source(request.args.get("source"))
    lang = request.args.get("lang")
    detailed = _db.focus_switch_detailed(days=days, source=source)
    by_sid = detailed.get("by_scenario", {})

    per_scenario = []
    for sc in scenario_store.scorable():
        stats = by_sid.get(sc.id, {})
        switches = stats.get("switches", 0)
        misses = stats.get("misses", 0)
        max_delta = stats.get("max_delta", 0.0)
        avg_delta = stats.get("avg_delta", 0.0)
        miss_rate = round(misses / switches, 3) if switches else 0.0

        if switches < C_MEDIUM_MIN_SWITCHES:
            status = "INSUFFICIENT_DATA"
            reason = (f"only {switches} focus switches in last {days}d "
                      f"(need >= {C_MEDIUM_MIN_SWITCHES})")
        elif miss_rate > C_MEDIUM_MISS_THRESHOLD:
            status = "CONSIDER_C_MEDIUM"
            reason = (f"miss_rate {miss_rate:.1%} exceeds threshold "
                      f"{C_MEDIUM_MISS_THRESHOLD:.1%} "
                      f"(|delta| > {C_MEDIUM_DELTA_MISS} on "
                      f"{misses}/{switches} switches)")
        else:
            status = "LITE_SUFFICIENT"
            reason = (f"miss_rate {miss_rate:.1%} within threshold "
                      f"{C_MEDIUM_MISS_THRESHOLD:.1%}")

        per_scenario.append({
            "scenario_id": sc.id,
            "label": _scenario_label(sc, lang),
            "switches": switches,
            "misses": misses,
            "miss_rate": miss_rate,
            "avg_delta": avg_delta,
            "max_delta": max_delta,
            "status": status,
            "reason": reason,
        })

    return jsonify({
        "period_days": days,
        "source": source or "all",
        "config": {
            "delta_miss": C_MEDIUM_DELTA_MISS,
            "delta_miss_shadow": C_MEDIUM_DELTA_MISS_SHADOW,
            "miss_threshold": C_MEDIUM_MISS_THRESHOLD,
            "min_switches": C_MEDIUM_MIN_SWITCHES,
        },
        "scenarios": per_scenario,
    })


@bp.route("/api/analytics/calibration_advisory", methods=["GET"])
@_analytics_read
def api_calibration_advisory():
    """Weight calibration advisory: analyzes scenario participant weight
    distribution and suggests adjustments based on observed signal patterns.

    Also surfaces cross-scenario signal overlap — signals that contribute
    to multiple scenarios simultaneously, indicating shared threat vectors.
    """
    from radar.scenarios import scenario_store, derive_country_context, Role
    hours = _safe_int(request.args.get("hours", "168"), 168, min_val=1, max_val=720)
    cutoff = time.time() - hours * 3600

    advisories = []
    cross_scenario_countries: dict[str, list[str]] = {}  # country -> [scenario_ids]

    for sc in scenario_store.scorable():
        for cc in sc.participants:
            cross_scenario_countries.setdefault(cc, []).append(sc.id)

        # Analyze weight distribution for imbalances
        weights = [p.weight for p in sc.participants.values()
                   if p.role != Role.ADVERSARY]
        if not weights:
            continue
        max_w = max(weights)
        min_w = min(weights)

        # Check for zero-weight participants (dead weight)
        zero_weight = [cc for cc, p in sc.participants.items()
                       if p.weight == 0 and p.role != Role.ADVERSARY]

        # Check for extreme weight concentration
        if len(weights) >= 3 and max_w > 0:
            concentration = max_w / (sum(weights) / len(weights))
            if concentration > 3.0:
                advisories.append({
                    "scenario_id": sc.id,
                    "severity": "MEDIUM",
                    "type": "weight_concentration",
                    "detail": (f"Top participant weight ({max_w:.2f}) is "
                               f"{concentration:.1f}x the average — scoring "
                               f"is heavily dominated by one country"),
                })

        if zero_weight:
            advisories.append({
                "scenario_id": sc.id,
                "severity": "LOW",
                "type": "zero_weight_participant",
                "detail": (f"Participants {zero_weight} have weight=0 — "
                           f"their signals will not contribute to scoring"),
            })

        # Check if any non-adversary participant has no recent TL observations
        obs = _db.scenario_tl_timeseries(sc.id, hours=hours, limit=5)
        if not obs:
            advisories.append({
                "scenario_id": sc.id,
                "severity": "LOW",
                "type": "no_observations",
                "detail": f"No TL observations in last {hours}h",
            })

    # Cross-scenario overlap: countries appearing in 2+ scenarios
    overlap = {cc: sids for cc, sids in cross_scenario_countries.items()
               if len(sids) >= 2}

    return jsonify({
        "hours": hours,
        "advisories": advisories,
        "cross_scenario_overlap": overlap,
    })


@bp.route("/api/analytics/confidence_distribution", methods=["GET"])
@_analytics_read
def api_confidence_distribution():
    """LLM intel confidence distribution for pipeline tuning.

    Shows how confidence values are distributed across all LLM intel items
    and what fraction would qualify for auto_confirm under current thresholds.
    Use this to diagnose why intel is stuck pending — if most items are in the
    0.60-0.79 range, the LLM prompts need adjustment, not the thresholds.
    """
    hours = _safe_int(request.args.get("hours", "168"), 168, min_val=1, max_val=720)
    return jsonify(_db.intel_confidence_distribution(hours=hours))


@bp.route("/api/analytics/scenario_phases", methods=["GET"])
@_analytics_read
def api_scenario_phases():
    """Scenario implementation phase annotation for operational awareness.

    Returns each scenario's current state with calibration and migration
    readiness indicators based on observation history.
    """
    from radar.scenarios import scenario_store
    history_start = _db.scenario_history_start()
    lang = request.args.get("lang")
    results = []
    for sc in scenario_store.all().values():
        obs_count = len(_db.scenario_tl_timeseries(sc.id, hours=720, limit=500))
        latest_tl = _db.scenario_tl_last(sc.id)

        # Determine operational readiness
        if obs_count == 0:
            phase = "uncalibrated"
        elif obs_count < 100:
            phase = "warmup"
        else:
            phase = "operational"

        results.append({
            "scenario_id": sc.id,
            "label": _scenario_label(sc, lang),
            "state": sc.state,
            "enabled": sc.enabled,
            "is_scorable": sc.is_scorable,
            "tier": sc.tier,
            "phase": phase,
            "observation_count": obs_count,
            "latest_tl": latest_tl,
            "history_starts_at": history_start,
        })
    return jsonify({"scenarios": results})


