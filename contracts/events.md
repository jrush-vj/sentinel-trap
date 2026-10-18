# SENTINEL-TRAP event contract

Every service sends events as JSON to the monitor at `POST http://monitor:9000/events`. The body is either a single event or a list of events.
Senders do not wait for this call to succeed. The gateway buffers up to 500 events in memory if the monitor is down.

```jsonc
{
  "id": "uuid",                 // uuid4 string
  "ts": "ISO8601 UTC",          // e.g. 2026-10-18T12:00:00.000Z
  "session_id": "string",       // gateway st_session cookie (or synthetic id for system events)
  "fingerprint": "string",      // sha256(ip | user-agent | st_session)[:16]
  "attacker_ip": "string",
  "channel": "web | prompt | shell | system",
  "action": "request | blocked | routed_to_honeypot | honeypot_interaction | canary_hit | banned | session_ended | rule_learned | rule_rejected | marked_safe | learned_rule_caught",
  "payload": "string",          // truncated to 500 chars
  "verdict": "clean | suspicious | malicious",
  "risk": 0,                    // integer 0-10
  "rule_id": "string or null",
  "detail": "free text"
}
```

## Channels
| channel  | meaning |
|----------|---------|
| `web`    | HTTP requests to the customer lookup / generic web paths |
| `prompt` | requests to the AI assistant (`/api/chat`) |
| `shell`  | reserved for the future SSH shell honeypot (`shell_honeypot/`) |
| `system` | internal events: bans, learning, mark-safe |

## Actions and who emits them
| action | emitter | meaning |
|--------|---------|---------|
| `request` | gateway | clean request proxied to the real app |
| `blocked` | gateway | a banned fingerprint/IP got an instant 403 |
| `routed_to_honeypot` | gateway | first detection: rules flagged the request, so the attacker is silently rerouted |
| `honeypot_interaction` | honeypot | every action of a trapped attacker (detail = what fake data was served) |
| `canary_hit` | gateway | the attacker reused a canary token or touched a canary endpoint (risk 10) |
| `banned` | gateway | fingerprint + IP added to the ban store |
| `session_ended` | honeypot / gateway | honeypot session is over (kick-out, canary, idle). The monitor then runs report + learning |
| `rule_learned` | gateway | an LLM/offline-proposed rule passed validation and is active |
| `rule_rejected` | gateway | a proposed rule failed validation (detail = reason) |
| `marked_safe` | gateway | an operator corrected a false positive (unban / whitelist) |
| `learned_rule_caught` | gateway | a *learned* rule caught a request that the built-in rules alone would not have flagged as malicious |

## Optional extension fields
Receivers must ignore unknown fields. The monitor uses these when they are present:
- `extra` (object): structured data, e.g. `{"actions": 3, "max_actions": 8}` on honeypot events, the full rule on `rule_learned`, or `{"builtin_score": 0, "builtin_verdict": "clean"}` on `learned_rule_caught`.

The monitor also broadcasts its own analyst messages on `WS /ws`, using `{"type": "analysis" | "report" | "stats", ...}`. These are kept separate from events and are not stored as events.
