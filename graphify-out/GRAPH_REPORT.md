# Graph Report - sentinel-trap  (2026-10-18)

## Corpus Check
- 112 files · ~542,118 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 17 file(s) not represented in the graph (top: (none) 7, .woff2 5, .css 4)

## Summary
- 1029 nodes · 2183 edges · 47 communities (37 shown, 10 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 70 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `3eec1851`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_accounts.py
- Event contract schema
- llm.py
- RuleEngine
- monitor/main.py
- honeypot/main.py
- monitor/static/app.js
- Hub
- app/main.py
- validate
- Analyst
- MockRunner
- EventSender
- demo.ps1
- demo.sh script
- prompts.py
- app/static/app.js
- assets.mjs
- verify.sh
- pytest
- test_llm.sh
- draw.mjs
- stop_attack
- gateway/main.py
- commit_ban
- inspect.mjs
- 4. Recipes
- The run
- make_event
- Imagery
- The study
- SENTINEL-TRAP — project history & handoff
- lint.mjs
- Colour
- Layout
- Tells — the dated registry
- Type
- cdp.mjs
- Page
- Words
- proxy.py
- Critique — judging the render
- tasteskill v2 (`design-taste-frontend`)
- Frontend Design
- rules.mjs
- Web Interface Guidelines

## God Nodes (most connected - your core abstractions)
1. `getOne()` - 31 edges
2. `now_iso()` - 28 edges
3. `gateway()` - 27 edges
4. `search()` - 22 edges
5. `RuleEngine` - 22 edges
6. `validate()` - 21 edges
7. `getVideo()` - 19 edges
8. `Rule` - 19 edges
9. `Analyst` - 19 edges
10. `make_event()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `Bugs found and fixed along the way` --references--> `_is_tautology()`  [INFERRED]
  history.md → honeypot/fakes.py
- `Rolling hash chain` --semantically_similar_to--> `Log-tamper detection`  [INFERRED] [semantically similar]
  logwatch/README.md → shell_honeypot/README.md
- `Fake SSH shell honeypot` --semantically_similar_to--> `Honeypot`  [INFERRED] [semantically similar]
  shell_honeypot/README.md → README.md
- `test_only_meaningful_ips_are_banned()` --calls--> `bannable_ip()`  [EXTRACTED]
  tests/test_accounts.py → gateway/main.py
- `test_banned_session_stays_banned_after_session_end()` --calls--> `build_sessions()`  [EXTRACTED]
  tests/test_accounts.py → monitor/main.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Gateway deterministic decision path** — readme_gateway, readme_fingerprint, readme_ban_store, readme_rule_engine, readme_app, readme_honeypot [EXTRACTED 1.00]
- **SOC dashboard panel set** — monitor_static_index_soc_dashboard, monitor_static_index_attack_flow_panel, monitor_static_index_live_event_feed_panel, monitor_static_index_honeypot_activity_panel, monitor_static_index_ai_analyst_panel, monitor_static_index_memory_learning_panel [EXTRACTED 1.00]
- **Self-improving learning loop** — readme_llm_analyst, readme_learning_loop, readme_validator, readme_rule_engine, contracts_events_rule_learned, contracts_events_learned_rule_caught [INFERRED 0.85]

## Communities (47 total, 10 thin omitted)

### Community 0 - "test_accounts.py"
Cohesion: 0.09
Nodes (37): add_ban(), add_whitelist(), conn(), get_attacker(), idle_eligible_sessions(), is_banned(), list_bans(), mark_ended() (+29 more)

### Community 1 - "Event contract schema"
Cohesion: 0.05
Nodes (54): Customer lookup, NovaMind Assistant (chat), NovaMind AI Support Desk, banned action, blocked action, canary_hit action, shell channel, Event contract schema (+46 more)

### Community 2 - "llm.py"
Cohesion: 0.06
Nodes (29): _load_secret(), _sig(), sign(), verify(), Breaker, chat(), chat_json(), config_path() (+21 more)

### Community 3 - "RuleEngine"
Cohesion: 0.07
Nodes (23): normalize(), normalize_variants(), builtin_rules(), Rule, RuleEngine, test_builtin_rules_flag_log_injection(), test_learned_log_rule_passes_validation_and_generalizes(), test_disabled_rule_does_not_affect_real_attacks() (+15 more)

### Community 4 - "monitor/main.py"
Cohesion: 0.05
Nodes (47): action_counts(), conn(), distinct_count(), insert_analysis(), insert_event(), recent_analyses(), recent_events(), reset() (+39 more)

### Community 5 - "honeypot/main.py"
Cohesion: 0.09
Nodes (33): canary_token(), _fake_api_key_rows(), fake_chat_leak(), fake_customer_response(), _fake_schema_rows(), _fake_secret_rows(), _is_tautology(), admin_decoy() (+25 more)

### Community 6 - "monitor/static/app.js"
Cohesion: 0.08
Nodes (51): acct(), addCommentary(), addFeed(), adminHeaders(), adminToken(), api(), banner(), CAT (+43 more)

### Community 8 - "app/main.py"
Cohesion: 0.10
Nodes (27): append_log(), check_user(), connect(), create_user(), customer_search(), db_path(), _hash(), log_path() (+19 more)

### Community 9 - "validate"
Cohesion: 0.14
Nodes (18): _get_pool(), _match_worker(), _matches_any(), _reset_pool(), safe_search(), validate(), ValidationResult, test_accepts_generalized_prompt_injection() (+10 more)

### Community 10 - "Analyst"
Cohesion: 0.17
Nodes (4): Analyst, test_analyst_learns_live_then_is_ready(), broadcast(), run()

### Community 14 - "demo.sh script"
Cohesion: 0.60
Nodes (5): pause(), req(), reqb(), demo.sh script, hdr()

### Community 15 - "prompts.py"
Cohesion: 0.53
Nodes (4): commentary_user(), propose_user(), report_user(), wrap()

### Community 16 - "app/static/app.js"
Cohesion: 0.33
Nodes (11): bubble(), call(), chat, esc(), loadLogs(), post(), send(), show() (+3 more)

### Community 17 - "assets.mjs"
Cohesion: 0.07
Nodes (85): AIC_FIELDS, AIC_HEADERS, applyThumb(), ARCHIVE_LICENCE, args, argv, base(), clock() (+77 more)

### Community 19 - "pytest"
Cohesion: 0.67
Nodes (3): tests service (pytest profile), pytest, fastapi

### Community 21 - "draw.mjs"
Cohesion: 0.09
Nodes (39): adjustments(), argv, assetQueries(), ASSETS_PATH, briefStop(), briefWords(), deal(), dealHero() (+31 more)

### Community 23 - "gateway/main.py"
Cohesion: 0.14
Nodes (16): bannable_ip(), channel_of(), client_ip(), gateway(), handle_honeypot_action(), has_canary(), identity(), inspect_fields() (+8 more)

### Community 24 - "commit_ban"
Cohesion: 0.14
Nodes (14): admin_ban(), admin_ban_account(), admin_bans(), admin_end_all(), admin_mark_safe(), admin_propose(), admin_reset(), admin_rules() (+6 more)

### Community 25 - "inspect.mjs"
Cohesion: 0.10
Nodes (13): allow, args, asJson, fails, HEIGHT, merged, outDir, report (+5 more)

### Community 27 - "4. Recipes"
Cohesion: 0.10
Nodes (19): 1. The budget, 2. Four questions before any animation, 3. Tokens, 4. Recipes, 5. Signature moves, 6. Reduced motion and performance, 7. What gives generated motion away, Accordion (+11 more)

### Community 29 - "The run"
Cohesion: 0.12
Nodes (16): 10. Report, 1. Read the brief and the project, 2. Write the argument, 3. Draw the direction, 4. Find the idea, 5. Write the words, 6. Build it, still, 7. Gate (+8 more)

### Community 30 - "make_event"
Cohesion: 0.17
Nodes (4): idle_sweeper(), lifespan(), make_event(), truncate()

### Community 32 - "Imagery"
Cohesion: 0.14
Nodes (13): 10. Markup and credits, 11. Video, 1. What the study measured, 2. Decide what imagery exists, 3. Real pictures from the open collections, 4. The dealt photographs, 5. Cropping and placing, 6. Treatment (+5 more)

### Community 33 - "The study"
Cohesion: 0.14
Nodes (13): 10. The 25 highest-scored sites and their ideas, 11. How the skill was tested, 1. Method and its limits, 2. Scores, 3. Where the idea comes from, 4. Headlines, 5. Type, 6. Devices: what separates strong from weak, and what does not (+5 more)

### Community 34 - "SENTINEL-TRAP — project history & handoff"
Cohesion: 0.14
Nodes (13): 1. What the project is, 2. Environment / setup facts, 3. Key decisions (user-approved), 4. Architecture (short), 5. Progress log (all committed & pushed), 6. How to run & test, 7. Working conventions (from CLAUDE.md / user preferences), 8. Open items / ideas (+5 more)

### Community 36 - "lint.mjs"
Cohesion: 0.15
Nodes (12): line(), args, asJson, byId, EXT, files, findings, R (+4 more)

### Community 37 - "Colour"
Cohesion: 0.17
Nodes (11): 1. What the study measured, 2. The roles, 3. Proportion, 4. Surfaces without lines or shadows, 5. Colour fields, 6. Dark pages, 7. Colour and photographs, 8. Contrast (+3 more)

### Community 38 - "Layout"
Cohesion: 0.17
Nodes (11): 1. What strong pages do, 2. Margins and the grid, 3. Where text sits, 4. Empty space, 5. Sections: carry the idea, vary the arrangement, 6. Navigation, 7. Endings, 8. The phone is a second composition (+3 more)

### Community 39 - "Tells — the dated registry"
Cohesion: 0.18
Nodes (10): 1. First wave (2023–2024), 2. Second wave (2025), 3. Third wave (2025–2026): the "fix" that became the look, 4. Gallery fashion, banned as house style, 5. Structural tells, 6. Copy tells, 7. Motion tells, 8. Why removal is not enough (+2 more)

### Community 40 - "Type"
Cohesion: 0.18
Nodes (10): 1. What the study measured, 2. The scale: few sizes, far apart, 3. Setting display type, 4. Setting text, 5. Loading the fonts properly, 6. One family or two, 7. Details that separate set type from typed text, 8. Mistakes the inspector cannot see (+2 more)

### Community 43 - "Words"
Cohesion: 0.20
Nodes (9): 1. Write the argument first, 2. The two-line headline, 3. Headline shapes that work, 4. Supporting line, body, buttons, 5. Proof without inventing it, 6. Things that read as generated, 7. Micro-typography, Contents (+1 more)

### Community 44 - "proxy.py"
Cohesion: 0.25
Nodes (3): aclose(), client(), forward()

### Community 45 - "Critique — judging the render"
Cohesion: 0.22
Nodes (8): 1. How to look, 2. The score, 3. Caps, 4. Writing the critique, 5. What to fix first, 6. When to stop, Contents, Critique — judging the render

### Community 46 - "tasteskill v2 (`design-taste-frontend`)"
Cohesion: 0.29
Nodes (6): Contents, How it works, Install, Notes, Requirements, tasteskill v2 (`design-taste-frontend`)

### Community 47 - "Frontend Design"
Cohesion: 0.29
Nodes (6): Design principles, Frontend Design, Ground your designs in the subject matter, More on writing in design, Process: plan, review against the brief, build, critique, Restraint and self-critique

### Community 48 - "rules.mjs"
Cohesion: 0.53
Nodes (5): colourFamily(), hexToHsl(), inRange(), judge(), RULE_IDS

### Community 49 - "Web Interface Guidelines"
Cohesion: 0.40
Nodes (4): Guidelines Source, How It Works, Usage, Web Interface Guidelines

## Knowledge Gaps
- **16 isolated node(s):** `Customer lookup`, `NovaMind Assistant (chat)`, `monitor service`, `Attack Flow panel`, `Live Event Feed panel` (+11 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 386 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `now_iso()` connect `llm.py` to `test_accounts.py`, `RuleEngine`, `monitor/main.py`, `honeypot/main.py`, `app/main.py`, `Analyst`, `gateway/main.py`, `commit_ban`, `make_event`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `search()` (e.g. with `searchAic()` and `searchArchive()`) actually correct?**
  _`search()` has 7 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Customer lookup`, `NovaMind Assistant (chat)`, `monitor service` to the rest of the system?**
  _16 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `test_accounts.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0889894419306184 - nodes in this community are weakly interconnected._
- **Why does `Flow` connect `inspect.mjs` to `monitor/static/app.js`?**
  _High betweenness centrality (0.024) - this node is a cross-community bridge._
- **Should `Event contract schema` be split into smaller, more focused modules?**
  _Cohesion score 0.05388471177944862 - nodes in this community are weakly interconnected._
- **Should `llm.py` be split into smaller, more focused modules?**
  _Cohesion score 0.0636523266022827 - nodes in this community are weakly interconnected._