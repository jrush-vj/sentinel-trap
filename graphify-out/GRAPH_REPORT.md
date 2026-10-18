# Graph Report - sentinel-trap  (2026-10-18)

## Corpus Check
- Corpus is ~21,333 words - fits in a single context window. You may not need a graph.

## Summary
- 521 nodes · 1150 edges · 21 communities (14 shown, 7 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 45 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Gateway Core & Deps
- Domain Concepts & Events
- Offline Analyst Fallbacks
- Payload Normalization & Clean Corpus
- Monitor & Analyst Orchestration
- Honeypot Fake Data & Canaries
- Dashboard UI
- App Seeded Database
- NovaMind App Service
- Rule Validator
- Analyst Worker
- Mock Event Generator
- Community 12
- Community 13
- Community 14
- Community 15
- Community 16
- Community 17
- Community 18
- Community 19
- Community 20

## God Nodes (most connected - your core abstractions)
1. `gateway()` - 22 edges
2. `RuleEngine` - 19 edges
3. `validate()` - 19 edges
4. `now_iso()` - 19 edges
5. `conn()` - 16 edges
6. `make_event()` - 16 edges
7. `Rule` - 15 edges
8. `load_config()` - 15 edges
9. `normalize_variants()` - 14 edges
10. `Analyst` - 13 edges

## Surprising Connections (you probably didn't know these)
- `Fake SSH shell honeypot` --semantically_similar_to--> `Honeypot`  [INFERRED] [semantically similar]
  shell_honeypot/README.md → README.md
- `Rolling hash chain` --semantically_similar_to--> `Log-tamper detection`  [INFERRED] [semantically similar]
  logwatch/README.md → shell_honeypot/README.md
- `routed_to_honeypot action` --conceptually_related_to--> `Honeypot`  [INFERRED]
  contracts/events.md → README.md
- `Honeypot Activity panel` --references--> `Honeypot`  [INFERRED]
  monitor/static/index.html → README.md
- `banned action` --conceptually_related_to--> `Ban store (memory)`  [INFERRED]
  contracts/events.md → README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Gateway deterministic decision path** — readme_gateway, readme_fingerprint, readme_ban_store, readme_rule_engine, readme_app, readme_honeypot [EXTRACTED 1.00]
- **Self-improving learning loop** — readme_llm_analyst, readme_learning_loop, readme_validator, readme_rule_engine, contracts_events_rule_learned, contracts_events_learned_rule_caught [INFERRED 0.85]
- **SOC dashboard panel set** — monitor_static_index_soc_dashboard, monitor_static_index_attack_flow_panel, monitor_static_index_live_event_feed_panel, monitor_static_index_honeypot_activity_panel, monitor_static_index_ai_analyst_panel, monitor_static_index_memory_learning_panel [EXTRACTED 1.00]

## Communities (21 total, 7 thin omitted)

### Community 0 - "Gateway Core & Deps"
Cohesion: 0.05
Nodes (52): admin_ban(), admin_bans(), admin_mark_safe(), admin_propose(), admin_reset(), admin_rules(), admin_toggle(), client_ip() (+44 more)

### Community 1 - "Domain Concepts & Events"
Cohesion: 0.05
Nodes (54): Customer lookup, NovaMind Assistant (chat), NovaMind AI Support Desk, banned action, blocked action, canary_hit action, shell channel, Event contract schema (+46 more)

### Community 2 - "Offline Analyst Fallbacks"
Cohesion: 0.08
Nodes (25): commentary(), propose(), report(), chat(), chat_json(), config_path(), extract_json(), LLMUnavailable (+17 more)

### Community 3 - "Payload Normalization & Clean Corpus"
Cohesion: 0.08
Nodes (21): normalize(), normalize_variants(), builtin_rules(), Rule, RuleEngine, test_disabled_rule_does_not_affect_real_attacks(), test_disabling_eager_rule_clears_false_positive(), test_toggle_learned_rule() (+13 more)

### Community 4 - "Monitor & Analyst Orchestration"
Cohesion: 0.11
Nodes (22): api_analyses(), api_bans(), api_events(), api_llm_config(), api_llm_config_save(), api_llm_status(), api_llm_test(), api_mark_safe() (+14 more)

### Community 5 - "Honeypot Fake Data & Canaries"
Cohesion: 0.14
Nodes (20): canary_token(), _fake_api_key_rows(), fake_chat_leak(), fake_customer_response(), _fake_schema_rows(), _fake_secret_rows(), _is_tautology(), admin_decoy() (+12 more)

### Community 6 - "Dashboard UI"
Cohesion: 0.13
Nodes (28): addCommentary(), addFeed(), adminHeaders(), adminToken(), api(), connectWS(), esc(), evClass() (+20 more)

### Community 7 - "App Seeded Database"
Cohesion: 0.12
Nodes (15): connect(), customer_search(), db_path(), seed(), action_counts(), conn(), distinct_count(), insert_analysis() (+7 more)

### Community 8 - "NovaMind App Service"
Cohesion: 0.09
Nodes (8): canned_reply(), chat(), customers(), healthz(), index(), offline_chat(), _startup(), Hub

### Community 9 - "Rule Validator"
Cohesion: 0.13
Nodes (18): _get_pool(), _match_worker(), _matches_any(), _reset_pool(), safe_search(), validate(), ValidationResult, test_accepts_generalized_prompt_injection() (+10 more)

### Community 14 - "Community 14"
Cohesion: 0.60
Nodes (5): pause(), req(), reqb(), demo.sh script, hdr()

### Community 15 - "Community 15"
Cohesion: 0.53
Nodes (4): commentary_user(), propose_user(), report_user(), wrap()

### Community 16 - "Community 16"
Cohesion: 0.50
Nodes (3): bubble(), chat, send()

### Community 19 - "Community 19"
Cohesion: 0.67
Nodes (3): tests service (pytest profile), pytest, fastapi

## Knowledge Gaps
- **16 isolated node(s):** `Offline analyst`, `Memory`, `request action`, `blocked action`, `honeypot_interaction action` (+11 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 139 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `now_iso()` connect `Gateway Core & Deps` to `Offline Analyst Fallbacks`, `Payload Normalization & Clean Corpus`, `Monitor & Analyst Orchestration`, `Analyst Worker`, `Community 17`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **What connects `Offline analyst`, `Memory`, `request action` to the rest of the system?**
  _16 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Gateway Core & Deps` be split into smaller, more focused modules?**
  _Cohesion score 0.053750597228858096 - nodes in this community are weakly interconnected._
- **Why does `validate()` connect `Rule Validator` to `Gateway Core & Deps`, `Payload Normalization & Clean Corpus`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Should `Domain Concepts & Events` be split into smaller, more focused modules?**
  _Cohesion score 0.05388471177944862 - nodes in this community are weakly interconnected._
- **Why does `RuleEngine` connect `Payload Normalization & Clean Corpus` to `Gateway Core & Deps`, `App Seeded Database`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Should `Offline Analyst Fallbacks` be split into smaller, more focused modules?**
  _Cohesion score 0.07542087542087542 - nodes in this community are weakly interconnected._