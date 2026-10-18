# logwatch/ — DEFERRED (not built yet)

File-integrity / tamper monitoring for logs and JSON state, to be built later on a Proxmox homelab.

## Planned design
- Watch the shared `data/` artifacts (`events.db`, `rules.json`, `reputation.db`) and honeypot logs.
- Maintain a rolling hash chain (each record hashes the previous) so deletion or in-place edits of
  historical entries are detectable.
- On a detected gap/rewrite, emit a `channel=system` event (e.g. action `canary_hit` with a
  tamper detail) so the dashboard flags it and the analyst comments on it.
- Optional: append-only mirror of events to a second store for forensic comparison.

## Why deferred
Integrity monitoring matters most for the long-running shell honeypot and a multi-host deployment;
it is out of scope for the single-host hackathon demo, where the gateway is the only writer of each
DB and the demo is short-lived. The event schema already supports surfacing tamper alerts here.
