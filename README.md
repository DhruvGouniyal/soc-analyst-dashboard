# SOC Command Center

A security operations console for the Kali → Ubuntu → detection-engine lab pipeline.
Runs today on a seeded mock data layer; the dashboard swaps onto the real Ubuntu
collectors by setting one environment variable.

```
Kali (attacker) ──attacks──▶ Ubuntu (victim) ──logs──▶ Detection Engine ──▶ this dashboard
```

## Running it

```bash
npm install
npm run dev          # http://localhost:5173
```

| Script | What it does |
| --- | --- |
| `npm run dev` | Vite dev server with HMR |
| `npm run build` | Typecheck, then production build to `dist/` |
| `npm run preview` | Serve the production build |
| `npm run typecheck` | Types only |
| `npm run verify` | Headless check of the data + metrics layers (see below) |

`npm run verify` runs the generator, risk engine, and metrics without a browser and
asserts the derived numbers land in believable ranges. It exists because a dashboard
can render flawlessly while every figure on it is wrong — this catches that.

## Connecting the real Ubuntu backend

Set the backend URL and restart. No component changes.

```bash
# .env.local
VITE_SOC_API_URL=http://192.168.56.105:8000
```

`src/data/providers/index.ts` then returns `UbuntuSecurityEventProvider` instead of the
mock. That provider is complete working code — an HTTP + WebSocket client with
exponential-backoff reconnect — it simply has no server to talk to yet.

**Backend contract it expects:**

```
GET  {VITE_SOC_API_URL}/api/events?since=<epoch_ms>
     -> { events: RawEvent[], hosts: RawHost[] }

WS   {VITE_SOC_API_URL}/ws/events
     -> { type: 'event', payload: RawEvent }
     -> { type: 'hosts', payload: RawHost[] }
```

If your field names differ, change **only** `normalizeEvent()` in
`UbuntuSecurityEventProvider.ts`. It is the single translation point between
backend-shaped data and the dashboard schema; nothing downstream sees raw payloads.

Until a backend is configured the sidebar reads **Mock Data Source** rather than
**Backend Connected**, so the data's origin is never ambiguous.

## Architecture

```
src/
  types/security.ts          Canonical domain model — every layer speaks these types
  config/
    severity.ts              Severity weights & ranks (domain only, portable to a backend)
    theme.ts                 Severity/status → visual treatment (the only place styling lives)
    eventTypes.ts            Detection catalog: labels, MITRE mapping, analyst actions
    mitre.ts                 MITRE ATT&CK technique catalog
    navigation.ts            Sidebar structure
  data/
    topology.ts              The lab network: hosts, IPs, source profiles
    random.ts                Seeded PRNG (mulberry32)
    eventFactory.ts          Builds events with real Ubuntu-format log lines
    scenarios.ts             6 attack scenarios + the demo script
    backfill.ts              7-day seeded history + the shared ambient-event model
    providers/
      types.ts               SecurityEventProvider — the swap seam
      MockSecurityEventProvider.ts
      DemoSecurityEventProvider.ts
      UbuntuSecurityEventProvider.ts    ← real integration, awaiting a backend
      index.ts               Provider factory (reads VITE_SOC_API_URL)
  services/                  Framework-free logic
    riskEngine.ts            Security score + source/asset risk
    metrics.ts               KPIs, chart bucketing, top sources, host risk
    eventStore.ts            Retention, filtering, sorting, status transitions
    time.ts                  Shared time formatting
  state/SecurityFeedContext  Provider lifecycle + live state, shared app-wide
  hooks/                     useClock, useEventFilters
  components/                ui/ primitives, layout/ shell, dashboard/ panels
  pages/                     Dashboard, Alerts, Hosts, Placeholder
```

The rule throughout: **no component holds a literal number.** Every count, score, and
bar comes from `services/`, computed from the event set. That is what makes analyst
actions matter — resolving an alert lowers the queue and raises the security score
immediately, because they read the same state.

## Data model

`SecurityEvent` (`src/types/security.ts`) carries a `logSource` field mapping to the
real artifacts the victim will expose — `auth.log`, `syslog`, `audit.log`, Suricata
`eve.json`, netflow, process auditing — plus the verbatim `rawLog` line the detection
fired on. The mock synthesizes realistic lines; the Ubuntu provider passes real ones
through. Open any alert's detail panel to see them.

### Mock data properties

- **Seeded.** The 7-day backfill uses a fixed seed, so every reload shows identical
  history. Demos and screenshots stay reproducible.
- **Diurnal.** Activity follows a day/night curve. A flat distribution is the tell of
  fabricated data.
- **Pre-triaged.** Older events are mostly resolved, leaving a small live backlog — so
  the KPI counts read as a working triage queue, not a lifetime total.
- **Source profiles.** Each origin IP has a specialty (the Kali box runs a full kill
  chain; opportunistic scanners sweep ports; one host does credential stuffing), so
  "Top Attack Sources" reports genuinely different dominant threats per row.
- **Downsampled history.** Data older than 24h is generated at reduced density, the
  same rollup real SIEMs apply, so the 7-day chart has shape without holding a week of
  full-resolution events in memory.

## Security score

`services/riskEngine.ts`, isolated so it can be replaced by a real algorithm.

Severity weights are Critical 25 / High 10 / Medium 4 / Low 1. Only **unresolved**
events in the last 4 hours count, decayed by age (full weight under 1h, 0.6 to 2h, 0.3
beyond). Accumulated pressure maps onto a 0–100 deduction through a saturating curve,
so the score degrades smoothly and never pins at zero from volume alone.

Every tunable is a named constant at the top of the file. The panel shows each
severity's contribution, so the number is accountable rather than opaque.

## Demo mode

Toggle **DEMO MODE** in the header. It runs a scripted kill chain on a fixed cadence,
with a timeline strip showing which beat is playing:

```
00:00  Reconnaissance — port scan
00:05  Credential attack — SSH failures
00:10  Detection — brute force confirmed
00:15  Foothold — suspicious login succeeds
00:20  Escalation — root transition and exfiltration
```

It keeps the existing history so charts and KPIs retain context, then loops after a
pause. Demo mode always uses the scripted provider even when a backend is configured —
a presentation should never depend on live attack traffic arriving on cue.

## Notes

- Analyst actions (Block IP / Investigate / Mark Resolved) mutate dashboard state only.
  Blocking is source-wide: every open event from that IP moves to `blocked`. The detail
  panel states this explicitly rather than implying enforcement.
- Severity is never signalled by color alone — every badge carries an icon and a text
  label, so the console stays readable in grayscale and with color-vision deficiencies.
- Incidents, Network, Threat Intelligence, Logs, Reports, and Settings are deliberately
  out of scope for this phase and render an honest placeholder rather than a hollow page.
