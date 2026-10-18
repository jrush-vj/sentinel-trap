# shell_honeypot/ — DEFERRED (not built yet)

A fake SSH shell giving an "employee-level foothold", to be built later on a Proxmox homelab.
The SENTINEL-TRAP event schema already supports `channel=shell`, so events from here will flow into
the same monitor/dashboard with no changes.

## Planned design
- **asyncssh** server presenting a believable Linux prompt on a dedicated port.
- **Fake filesystem**: an in-memory tree (`/home/ops`, `/etc`, `/var/log`, `/opt/app`) with plausible
  files. Reads return crafted content; writes are accepted but discarded.
- **Canary `.env`**: `/opt/app/.env` holds a `nm_live_CANARY_*` key. Any later reuse of that token
  (on the gateway, in another service, or via an outbound call) triggers `canary_hit` → ban, exactly
  like the web honeypot.
- **Command analysis**: each command is emitted as a `channel=shell` honeypot event. The async analyst
  produces commentary/technique/MITRE just as it does for web/prompt channels.
- **Log-tamper detection**: commands that try to edit or truncate logs (`rm`, `>`, `truncate`, `sed -i`
  on `/var/log/*`, `history -c`) raise a high-risk event and end the session.

## Why deferred
Needs a longer-lived host and an isolated network segment to be safe and believable. The web +
prompt honeypot already proves the adaptive-defense + memory + self-correction story end to end.
