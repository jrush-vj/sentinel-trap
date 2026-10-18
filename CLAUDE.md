# SENTINEL-TRAP
Hackathon demo: adaptive security gateway. Attackers (SQLi / prompt injection) are silently routed to a honeypot, an LLM analyst narrates their actions on a live dashboard, they get banned, and the system learns new rules.

## Services (docker compose, project name sentinel-trap)
gateway :8080 public entry | monitor :9000 dashboard+analyst+events | app :8000 internal (deliberately vulnerable demo) | honeypot :8001 internal. app and honeypot must never publish ports.
Deferred, stubs only: shell_honeypot/, logwatch/.

## Non-negotiable rules
- Allow/block/route decisions come only from rules + the ban store. Never from the LLM, never waiting on the LLM in the attacker's request path.
- LLM output is untrusted: JSON-only, validated, never executed. Learned regexes must pass gateway/validator.py before activation.
- LLM URL/key/model live in data/llm_config.json (the Kaggle quick-tunnel URL changes each run). Never hardcode a model name in the UI.
- Event schema is contracts/events.md. Honeypot must look identical to the real app to the attacker.
- Secrets only via env. Do not edit .env.

## Commands
Run: `docker compose up --build -d` | Tests: `pytest tests -q` | Demo: `bash attacks/demo.sh`

## Efficiency rules (token budget)
- Architecture or "where is X" questions: use the graphify graph (graphify-out/GRAPH_REPORT.md) before grepping.
- Read file ranges, not whole files. Do not re-read a file you just edited.
- Never read: data/*.db, graphify-out/graph.json, lockfiles, logs, .env.
- Keep command output small: `docker compose logs --tail 40 <svc>`, `pytest -q | tail -n 30`.
- Use Edit for changes, not full rewrites. Batch independent tool calls in parallel.
- Use the Explore subagent for broad searches so raw results stay out of the main context.
- Suggest /compact when the context gets heavy.

## Skill routing
- Structure/dependency questions -> graphify. Before each commit and after each feature -> /ponytail-review.
- Ponytail stays on lite: never remove dashboard features, tests, validation, or security checks for brevity.
- Do not add features outside this file's scope.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
