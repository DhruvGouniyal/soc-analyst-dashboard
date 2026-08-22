# SOC Detection Engine

The backend for the SOC Command Center dashboard. Runs on the Ubuntu victim,
tails its logs, correlates real attack patterns, and serves them over the wire
contract the dashboard already speaks.

```
/var/log/auth.log ─┐
/var/log/kern.log ─┤─▶ parsers ─▶ detection engine ─▶ store ─┬─▶ GET /api/events
psutil telemetry ──┘                                          └─▶ WS  /ws/events
```

## Quick start on the Ubuntu victim

```bash
./deploy/preflight.sh          # read-only: reports what this host can detect
sudo ./deploy/install.sh       # user, venv, config, systemd unit, start
journalctl -u soc-engine -f
```

Then on the machine running the dashboard, set both to the victim's address:

```bash
# .env.local
VITE_SOC_API_URL=http://10.139.116.20:8000
VITE_SOC_VICTIM_IP=10.139.116.20
npm run dev     # RESTART it — VITE_ vars are build-time substitutions
```

The sidebar should change from **Mock Data Source** to **Backend Connected**.
If it doesn't, Vite wasn't restarted.

## What it actually detects

Seven of the dashboard's eleven event types have a real data source here. The
other four are **never emitted** — a dashboard that invents detections is worse
than one that admits a gap.

| Event type | Source | Severity |
|---|---|---|
| `ssh_failed_auth` | `Failed password for <user>` | medium (high on MaxAuthTries) |
| `suspicious_login` | `Failed password for invalid user` | medium |
| `successful_login` | `Accepted password/publickey` | low → **high** after ≥3 recent failures |
| `ssh_brute_force` | correlator: 5 failures / 60s | critical |
| `privilege_escalation` | `sudo:` / `su:` failures | high / critical |
| `port_scan` | `[UFW BLOCK]`: 10 distinct ports / 60s | high |
| `new_connection` | inbound socket-table sampling | low |

**Not emitted, and why:** `web_attack` (no web server or access log),
`malware_signature` (no signature engine), `suspicious_process` (polling cannot
catch short-lived processes — needs auditd or eBPF), `data_exfiltration`
(`net_io_counters` is per-interface, not per-peer, so attributing volume to a
destination IP would be a guess).

Confirming that `nmap -sS` produces **no** event before you enable ufw logging
is a useful check in itself: it proves the engine is not fabricating.

## Correlation

Two stateful detections do the work that raw log lines cannot.

**Brute force** — 5 weighted failures inside 60s emits one critical alert, then
a 300s per-source cooldown. Without the cooldown a 400-attempt hydra run would
emit ~396 identical alerts and bury the feed. `maximum authentication attempts
exceeded` counts as 3, because sshd only logs it after MaxAuthTries guesses.

**Port scan** — 10 **distinct** destination ports inside 60s. Distinct-port
counting is what separates a sweep from a client retrying one closed port
twenty times.

Both are driven entirely by each log line's own timestamp, never the wall clock.
That is what lets the startup backfill reproduce the brute-force events the last
24 hours actually contained, instead of collapsing a day of failures into one
window.

**Login escalation** is the highest-value correlation available from auth.log
alone: a login that succeeds within 900s of 3+ failures from the same source is
raised to high severity. That is what a successful brute force looks like.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests -q          # 43 tests
.venv/bin/python tools/contract_check.py     # validate the wire format
```

Run it against a synthetic log, with no Ubuntu VM at all:

```bash
python tools/simulate_authlog.py seed /tmp/auth.log     # 24h of history
SOC_AUTH_LOG=/tmp/auth.log .venv/bin/uvicorn soc_engine.main:app --port 8000
python tools/simulate_authlog.py live /tmp/auth.log     # append traffic
python tools/simulate_authlog.py attack /tmp/auth.log   # one brute-force burst
```

## Layout

```
soc_engine/
  models.py        WireEvent / WireHost — the contract gate, validated at the source
  config.py        Every tunable, read from the environment
  parsers/         syslog_ts (year inference) · sshd · ufw · records
  detect/          bruteforce · portscan · sessions · pipeline
  collectors/      logtail (rotation-safe) · authlog · ufwlog · telemetry
  store/           ring buffer · host registry
  api/             routes · connection manager
tools/             contract_check.py · simulate_authlog.py
deploy/            preflight.sh · install.sh · systemd unit · env template
```

## Things that will bite you

The dashboard's client is deliberately forgiving — it never rejects bad data, it
substitutes a plausible default. So these fail *silently*, producing a dashboard
that renders perfectly and shows the wrong thing. `models.py` and
`tools/contract_check.py` exist to turn each one into a loud failure.

| Mistake | Symptom |
|---|---|
| **No CORS** | The GET is blocked, and because the client only opens its socket after that GET resolves, it looks like a WebSocket problem. `/healthz` showing `clients: 0` while the dashboard is open is the tell. |
| **Seconds not milliseconds** | Everything renders in 1970; KPIs zero, chart flat. |
| **Missing `severity`** | Silently becomes `low` — the console reads calm during an active attack. |
| **Counting `pam_unix` lines** | Every `Failed password` is preceded by one. Counting them triples the failure rate and fires the correlator on a single typo. |
| **`time.time()` in a correlator** | Backfill emits zero historical brute-force events. |
| **More than one uvicorn worker** | Split store and split client set; the dashboard sees a fraction of reality. |
| **`host` ≠ a published host id** | Events join to no host: zero host risk, empty host filter. |
| **`SOC_VICTIM_IP` ≠ the dashboard's `VITE_SOC_VICTIM_IP`** | The monitored host ranks itself in Top Attack Sources. |
| **Ports as strings** | Become `null` — there are no `src_port`/`dest_port` aliases. |
| **Float `cpu`/`memory`** | The host table renders `23.400000000000002%`. |

## Security notes

- Runs as a dedicated **non-root** user in the `adm` group, which is how it reads
  `auth.log` (`root:adm 0640`). It never needs root.
- Binds `0.0.0.0` so the dashboard host can reach it; restrict with `ufw`, not by
  binding to a fixed address that breaks if the VM's IP changes.
- **No authentication.** This is a lab tool on a host-only network. Do not expose
  port 8000 to an untrusted network.
- Log lines are decoded with `errors="replace"` and rendered as text, never HTML —
  a username is attacker-controlled input and is treated as such.
