#!/usr/bin/env bash
# Quick check that your LLM endpoint (e.g. Kaggle llama-server via cloudflared) is reachable and
# OpenAI-compatible. Reads config from data/llm_config.json if present, else from env / args.
#
# Usage:
#   scripts/test_llm.sh                         # use data/llm_config.json or .env
#   scripts/test_llm.sh https://xxx.trycloudflare.com  my-api-key  qwen3.6-35b-a3b
#
# The URL may be given with or without a trailing slash and with or without /v1.
set -euo pipefail

CFG="data/llm_config.json"
BASE="${1:-}"; KEY="${2:-}"; MODEL="${3:-}"

if [[ -z "$BASE" && -f "$CFG" ]]; then
  BASE=$(python -c "import json;print(json.load(open('$CFG')).get('base_url',''))" 2>/dev/null || true)
  KEY=$(python -c "import json;print(json.load(open('$CFG')).get('api_key',''))" 2>/dev/null || true)
  MODEL=$(python -c "import json;print(json.load(open('$CFG')).get('model',''))" 2>/dev/null || true)
fi
BASE="${BASE:-${LLM_BASE_URL:-}}"; KEY="${KEY:-${LLM_API_KEY:-changeme}}"; MODEL="${MODEL:-${LLM_MODEL:-qwen3.6-35b-a3b}}"

if [[ -z "$BASE" || "$BASE" == *"YOUR-KAGGLE"* ]]; then
  echo "No LLM base URL configured. Pass one as arg 1, or set it in the dashboard (gear icon)." >&2
  exit 2
fi

# Normalize: strip trailing slash, ensure /v1 suffix.
BASE="${BASE%/}"
[[ "$BASE" == */v1 ]] || BASE="$BASE/v1"
URL="$BASE/chat/completions"

echo "POST $URL  (model=$MODEL)"
START=$(date +%s.%N)
RESP=$(curl -sS --max-time 15 -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $KEY" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word: pong\"}],\"max_tokens\":16,\"temperature\":0.2,\"chat_template_kwargs\":{\"enable_thinking\":false}}")
END=$(date +%s.%N)

echo "---"
echo "$RESP" | python -c "import sys,json;d=json.load(sys.stdin);print('reply:',d.get('choices',[{}])[0].get('message',{}).get('content','(none)'))" 2>/dev/null \
  || { echo "Non-JSON or error response:"; echo "$RESP"; exit 1; }
python -c "print('latency: %.2fs' % ($END - $START))" 2>/dev/null || true
echo "OK — endpoint is reachable. Paste this URL into the dashboard gear and toggle LLM on."
