# Out-of-Band (OOB) Callback System

## Why this exists

Every other SSRF/XXE check in SENTINEL relies on the target's HTTP *response*
reflecting some evidence back — a cloud metadata string, a file's contents. A
target that genuinely fetches an internal-only URL but shows the caller nothing
(the common, realistic "blind" case) is invisible to all of those checks. This
has been an explicitly documented gap since Phase 7/9. OOB closes it: instead of
inspecting the response, SENTINEL controls a URL the target is tricked into
calling, and directly observes whether that call happened.

## Architecture
sentinel oob listen --storage-path scan.db (operator starts this once, separately)
↓ (long-running, logs to the SAME db file)
sentinel scan test ... (with target.oob.enabled: true)
↓
SSRFScanner/XXEScanner generate a correlation ID,
embed it in a callback URL, send the payload
↓
OOBClient.register_and_wait() — records the correlation,
sleeps wait_seconds, checks for a matching interaction
↓
if the target called back → OOBListener already logged it
↓
confirmed = True → "critical" severity, "high" confidence finding

## Enabling it

```yaml
target:
  oob:
    enabled: true
    callback_base_url: "http://YOUR_REACHABLE_HOST:8888"
    wait_seconds: 4.0
```

`callback_base_url` must be reachable **from the target application**, not from
your machine running SENTINEL. For a local lab, that's usually the same
machine/network (`http://127.0.0.1:8888` or your LAN IP). For a real remote
target, you need a real publicly-reachable host — SENTINEL does not provision
this for you (no ngrok integration, no cloud listener). This is exactly why it's
disabled by default.

Start the listener (in its own terminal, before or during the scan):

```bash
sentinel oob listen --host 0.0.0.0 --port 8888 --storage-path scan.db
```

`--storage-path` must match the scan's own `storage_path` — the listener and the
scanner communicate entirely through that shared SQLite file.

## Confidence and severity

An OOB-confirmed finding (`detection_method: "oob_confirmed"` in metadata) is
`severity: critical`, `confidence: high` — the highest confidence any automated
check produces anywhere in SENTINEL (Phase 9's hard cap still applies: never
`"confirmed"`, but this is about as close as an automated signal gets, since it's
direct network-level proof, not a heuristic pattern match). Compare to the
existing reflection-based SSRF finding, which stays `confidence: low` precisely
because it's a heuristic.

## Known limitations

- **HTTP-level only.** A target that performs a raw DNS lookup for the callback
  host but never makes an HTTP request (some blind-SSRF variants) will NOT be
  caught — that needs an authoritative DNS listener, a real future enhancement,
  not built in this phase.
- **No wildcard-domain support.** The correlation ID is embedded as a URL path
  segment (`http://host:port/oob/<id>`), not a DNS subdomain. This works for
  every realistic HTTP-based SSRF/XXE case but means one listener host:port
  serves every correlation ID via path routing rather than per-request unique
  subdomains (which real tools like Burp Collaborator use for DNS-level
  confirmation too — out of scope here).
- **Adds real wall-clock time.** `register_and_wait()` blocks for
  `wait_seconds` per OOB-tested parameter. Only enable this for scans where
  blind SSRF/XXE confirmation is worth the slowdown.
- **No authentication on the listener.** The correlation ID's unguessability
  (20+ hex characters from `secrets.token_hex`) is the only protection against
  unrelated traffic being misattributed. Don't expose the listener more broadly
  than necessary.
- **SQLite multi-connection access.** The listener and every scan process open
  independent connections to the same SQLite file. Fine for this tool's
  low-concurrency, single-operator use; not designed for high-throughput
  concurrent scanning against the same database.
