#!/usr/bin/env bash
# End-to-end verifier: resets the demo, runs attacks/demo.sh non-interactively, then asserts the
# whole story via the monitor API. Exit 0 only if every check passes.
#
#   scripts/verify.sh [GATEWAY_HOST] [MONITOR_HOST]
set -uo pipefail
PY="$(command -v python || command -v python3)" || { echo "python or python3 is required" >&2; exit 1; }
GW="${1:-http://localhost:8080}"; MON="${2:-http://localhost:9000}"
ADMIN="${ADMIN_TOKEN:-dev-admin-token}"
PASS=0; FAIL=0
GRN=$'\e[32m'; RED=$'\e[31m'; RST=$'\e[0m'

jq_count() { "$PY" -c "import sys,json;d=json.load(sys.stdin);print(sum(1 for e in d if e.get('action')=='$1'))"; }
check() { # check "label" <actual> <op> <expected>
  local label="$1" actual="$2" op="$3" exp="$4"
  if [[ "$op" == "ge" && "$actual" -ge "$exp" ]] || [[ "$op" == "eq" && "$actual" == "$exp" ]]; then
    echo "  ${GRN}PASS${RST} $label ($actual)"; PASS=$((PASS+1))
  else echo "  ${RED}FAIL${RST} $label (got $actual, want $op $exp)"; FAIL=$((FAIL+1)); fi
}

echo "Resetting demo state…"
curl -s -H "Authorization: Bearer $ADMIN" -X POST "$MON/api/reset" >/dev/null; sleep 1
echo "Running demo.sh (auto mode)…"
DEMO_AUTO=1 ADMIN_TOKEN="$ADMIN" bash "$(dirname "$0")/../attacks/demo.sh" "$GW" "$MON" >/dev/null 2>&1
sleep 3

EVENTS=$(curl -s "$MON/api/events?limit=500")
STATS=$(curl -s "$MON/api/stats")
BANS=$(curl -s "$MON/api/bans")
RULES=$(curl -s "$MON/api/rules")

echo; echo "Assertions:"
check "legit requests proxied to app"   "$(echo "$EVENTS" | jq_count request)"            ge 3
check "attacks routed to honeypot"       "$(echo "$EVENTS" | jq_count routed_to_honeypot)"  ge 3
check "honeypot interactions"            "$(echo "$EVENTS" | jq_count honeypot_interaction)" ge 2
check "canary hit"                       "$(echo "$EVENTS" | jq_count canary_hit)"           ge 1
check "ban created"                      "$(echo "$EVENTS" | jq_count banned)"               ge 1
check "ban row present"                  "$(echo "$BANS" | "$PY" -c 'import sys,json;print(len(json.load(sys.stdin)))')" ge 1
check "return visit blocked (403)"       "$(echo "$EVENTS" | jq_count blocked)"              ge 1
check "rule learned"                     "$(echo "$EVENTS" | jq_count rule_learned)"         ge 1
check "learned rule caught the variant"  "$(echo "$EVENTS" | jq_count learned_rule_caught)"  ge 1
check "false positive corrected"         "$(echo "$EVENTS" | jq_count marked_safe)"          ge 1

echo
echo "Totals: ${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}"
[[ "$FAIL" -eq 0 ]] && echo "${GRN}END-TO-END OK${RST}" || echo "${RED}END-TO-END FAILED${RST}"
exit "$FAIL"
