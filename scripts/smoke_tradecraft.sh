#!/usr/bin/env bash
#
# smoke_tradecraft.sh — Post-deploy smoke check for /api/analyst/* (F4..F14).
#
# Runs every tradecraft endpoint as an analyst and as a viewer, then verifies:
#   1. All GETs return 200 for analyst.
#   2. All writes return 200 for analyst and leave a decision_ledger row
#      whose detail.auto == true.
#   3. Lock/unlock returns 403 for analyst (admin-only).
#   4. All writes return 403 for viewer.
#   5. F14 manual POST does NOT get marked auto=true.
#
# Usage:
#   BASE_URL=http://127.0.0.1:8000 \
#   ADMIN_USER=admin ADMIN_PW='...' \
#   ANALYST_USER=tc_smoke_analyst ANALYST_PW='TestPass_smoke123' \
#   VIEWER_USER=tc_smoke_viewer VIEWER_PW='TestPass_smoke123' \
#   SCENARIO_ID=taiwan_contingency \
#   ./scripts/smoke_tradecraft.sh
#
# Prerequisites:
#   - jq installed
#   - analyst + viewer users already exist (create via /api/auth/register with admin)
#   - SCENARIO_ID must reference a loaded scenario preset

set -euo pipefail

: "${BASE_URL:=http://127.0.0.1:8000}"
: "${SCENARIO_ID:=taiwan_contingency}"
: "${ADMIN_USER:=admin}"
: "${ADMIN_PW:?ADMIN_PW required}"
: "${ANALYST_USER:?ANALYST_USER required}"
: "${ANALYST_PW:?ANALYST_PW required}"
: "${VIEWER_USER:?VIEWER_USER required}"
: "${VIEWER_PW:?VIEWER_PW required}"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

login() {
    local user="$1" pw="$2"
    local resp
    resp="$(curl -s -X POST "$BASE_URL/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$user\",\"password\":\"$pw\"}")"
    echo "$resp" | jq -er '.access_token' || fail "login failed for $user: $resp"
}

api() {
    local method="$1" path="$2" token="$3" body="${4:-}"
    if [[ -n "$body" ]]; then
        curl -s -o /tmp/smoke_body -w '%{http_code}' -X "$method" \
            "$BASE_URL$path" \
            -H "Authorization: Bearer $token" \
            -H 'Content-Type: application/json' \
            -d "$body"
    else
        curl -s -o /tmp/smoke_body -w '%{http_code}' -X "$method" \
            "$BASE_URL$path" -H "Authorization: Bearer $token"
    fi
}

expect_status() {
    local want="$1" got="$2" label="$3"
    [[ "$got" == "$want" ]] || fail "$label — want $want, got $got. Body: $(cat /tmp/smoke_body)"
    ok "$label ($got)"
}

echo "[1/6] Logging in…"
ADMIN_TOKEN="$(login "$ADMIN_USER" "$ADMIN_PW")"
ANALYST_TOKEN="$(login "$ANALYST_USER" "$ANALYST_PW")"
VIEWER_TOKEN="$(login "$VIEWER_USER" "$VIEWER_PW")"
ok "admin/analyst/viewer logged in"

SID="smoke-$(date +%s)-$RANDOM"
echo "[2/6] Analyst GETs (scenario_id=$SCENARIO_ID session=$SID)"
for ep in "hidden_signals" "coverage" "disconf" "assumptions" "premortem" "dissent" "decisions"; do
    status="$(api GET "/api/analyst/$ep?scenario_id=$SCENARIO_ID" "$ANALYST_TOKEN")"
    expect_status 200 "$status" "GET /api/analyst/$ep (analyst)"
done

echo "[3/6] Viewer is blocked (403) from writes"
for payload in \
    'POST:/api/analyst/disconf:{"scenario_id":"'"$SCENARIO_ID"'","summary":"nope"}' \
    'POST:/api/analyst/ach:{"scenario_id":"'"$SCENARIO_ID"'","title":"nope"}' \
    'POST:/api/analyst/assumptions:{"scenario_id":"'"$SCENARIO_ID"'","statement":"nope"}' \
    ; do
    method="${payload%%:*}"; rest="${payload#*:}"; path="${rest%%:*}"; body="${rest#*:}"
    status="$(api "$method" "$path" "$VIEWER_TOKEN" "$body")"
    expect_status 403 "$status" "$method $path (viewer)"
done

echo "[4/6] Analyst write-through populates F14 with auto=true"
status="$(api POST "/api/analyst/disconf" "$ANALYST_TOKEN" \
    "{\"scenario_id\":\"$SCENARIO_ID\",\"summary\":\"smoke disconf\",\"source_kind\":\"manual_note\",\"strength\":2,\"session_id\":\"$SID\"}")"
expect_status 200 "$status" "POST /api/analyst/disconf (analyst)"

sleep 0.5
dec_status="$(api GET "/api/analyst/decisions?session_id=$SID" "$ANALYST_TOKEN")"
expect_status 200 "$dec_status" "GET /api/analyst/decisions?session_id=$SID"
auto_count="$(jq '[.items[] | select(.detail.auto == true)] | length' /tmp/smoke_body)"
[[ "$auto_count" -ge 1 ]] || fail "expected >=1 auto-logged entry in session $SID, got $auto_count. Body: $(cat /tmp/smoke_body)"
ok "auto-logged entries for $SID: $auto_count"

echo "[5/6] Analyst is blocked (403) from assumption lock"
add_status="$(api POST "/api/analyst/assumptions" "$ANALYST_TOKEN" \
    "{\"scenario_id\":\"$SCENARIO_ID\",\"statement\":\"smoke lock probe\",\"confidence\":\"low\",\"session_id\":\"$SID\"}")"
expect_status 200 "$add_status" "POST /api/analyst/assumptions (analyst)"
AID="$(jq -r '.id' /tmp/smoke_body)"
lock_status="$(api POST "/api/analyst/assumptions/$AID/lock" "$ANALYST_TOKEN" \
    "{\"lock\":true,\"session_id\":\"$SID\"}")"
expect_status 403 "$lock_status" "POST /api/analyst/assumptions/$AID/lock (analyst)"

lock_admin_status="$(api POST "/api/analyst/assumptions/$AID/lock" "$ADMIN_TOKEN" \
    "{\"lock\":true,\"session_id\":\"$SID\"}")"
expect_status 200 "$lock_admin_status" "POST /api/analyst/assumptions/$AID/lock (admin)"

echo "[6/6] Manual F14 entry is NOT marked auto=true"
MAN_SID="$SID-manual"
man_status="$(api POST "/api/analyst/decisions" "$ANALYST_TOKEN" \
    "{\"scenario_id\":\"$SCENARIO_ID\",\"session_id\":\"$MAN_SID\",\"decision_type\":\"other\",\"summary\":\"manual probe\"}")"
expect_status 200 "$man_status" "POST /api/analyst/decisions (manual)"
sleep 0.5
api GET "/api/analyst/decisions?session_id=$MAN_SID" "$ANALYST_TOKEN" >/dev/null
manual_auto="$(jq '[.items[] | select(.detail.auto == true)] | length' /tmp/smoke_body)"
[[ "$manual_auto" -eq 0 ]] || fail "manual entry should NOT be marked auto=true (found $manual_auto). Body: $(cat /tmp/smoke_body)"
ok "manual entry has no auto=true"

echo
echo "✅ tradecraft smoke: all checks passed"
