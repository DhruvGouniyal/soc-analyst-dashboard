/**
 * Historical event generation, shared by the mock and demo providers.
 *
 * Uses a fixed seed so every reload renders the same 24 hours — demos and
 * screenshots stay reproducible, and a moving baseline can't be mistaken for
 * real activity. Historical events are pre-triaged the way a working SOC queue
 * would be: old detections are mostly closed, leaving a small live backlog, so
 * the KPI counts read as a triage queue rather than a lifetime total.
 */
import type { EventStatus, EventType, SecurityEvent } from '@/types/security';
import { buildEvent } from './eventFactory';
import { createRng, weightedPick, type Rng } from './random';
import { ALL_SCENARIOS, materializeScenario } from './scenarios';
import {
  ATTACKER_IP,
  EXTERNAL_SCANNER_IP,
  OPPORTUNISTIC_SOURCES,
  SECONDARY_ATTACKER_IP,
} from './topology';

/** Full-fidelity recent window. KPIs and the default chart range use this. */
export const HISTORY_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Total retained history. Anything older than `HISTORY_WINDOW_MS` is generated
 * at reduced density — the same rollup behavior real SIEMs apply to aged data —
 * so the 7-day chart has shape without holding a week of full-resolution events
 * in memory.
 */
export const RETENTION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const AGED_DENSITY_DIVISOR = 6;

const BACKFILL_SEED = 0x50c9a1;

/**
 * Share of ambient traffic that originates *from* the victim rather than
 * against it — routine outbound connections, plus the occasional transfer
 * large enough to look like exfiltration.
 */
const OUTBOUND_SHARE = 0.53;

const OUTBOUND_MIX: readonly (readonly [EventType, number])[] = [
  ['new_connection', 97],
  ['data_exfiltration', 3],
];

/**
 * Per-source behavioral profiles.
 *
 * Each origin has a specialty, which is how real telemetry looks: a mass
 * scanner sweeps ports, a credential-stuffing host hammers auth, the lab's
 * Kali box runs a full kill chain. Drawing every source from one shared
 * distribution made every row of "Top Attack Sources" report the same dominant
 * threat, which told an analyst nothing.
 */
export interface SourceProfile {
  ip: string;
  /** Relative share of inbound traffic from this origin. */
  weight: number;
  mix: readonly (readonly [EventType, number])[];
}

export const SOURCE_PROFILES: readonly SourceProfile[] = [
  {
    // The lab attacker: full kill chain, and the only source that escalates.
    // Weighted toward authentication noise, because that is what sustained
    // attacks actually generate most of — the severe stages are punctuation,
    // not the baseline. Keeping them rare also leaves the security score room
    // to move visibly when a real burst lands.
    ip: ATTACKER_IP,
    weight: 48,
    mix: [
      ['ssh_failed_auth', 38],
      ['suspicious_login', 16],
      ['successful_login', 12],
      ['port_scan', 10],
      ['web_attack', 9],
      ['suspicious_process', 6],
      ['ssh_brute_force', 4],
      ['malware_signature', 3],
      ['privilege_escalation', 2],
    ],
  },
  {
    // Credential guessing against accounts that mostly do not exist.
    ip: SECONDARY_ATTACKER_IP,
    weight: 20,
    mix: [
      ['suspicious_login', 46],
      ['ssh_failed_auth', 34],
      ['successful_login', 12],
      ['port_scan', 8],
    ],
  },
  {
    // Opportunistic service enumeration.
    ip: EXTERNAL_SCANNER_IP,
    weight: 12,
    mix: [
      ['port_scan', 58],
      ['web_attack', 32],
      ['suspicious_login', 10],
    ],
  },
  {
    ip: OPPORTUNISTIC_SOURCES[0],
    weight: 9,
    mix: [
      ['web_attack', 62],
      ['port_scan', 28],
      ['suspicious_login', 10],
    ],
  },
  {
    ip: OPPORTUNISTIC_SOURCES[1],
    weight: 6,
    mix: [
      ['suspicious_login', 52],
      ['ssh_failed_auth', 33],
      ['port_scan', 15],
    ],
  },
  {
    ip: OPPORTUNISTIC_SOURCES[2],
    weight: 5,
    mix: [
      ['port_scan', 44],
      ['malware_signature', 30],
      ['web_attack', 26],
    ],
  },
];

const SOURCE_WEIGHTS = SOURCE_PROFILES.map((p) => [p, p.weight] as const);

/**
 * Produces one ambient event.
 *
 * Shared by the backfill and the live mock stream so historical and incoming
 * data are drawn from exactly the same model — otherwise the feed would drift
 * away from the history the charts show.
 */
export function createAmbientEvent(rng: Rng, timestamp: number): SecurityEvent {
  if (rng() < OUTBOUND_SHARE) {
    // Victim-originated: the factory defaults the source to the victim.
    return buildEvent({ eventType: weightedPick(rng, OUTBOUND_MIX), timestamp, rng });
  }
  const profile = weightedPick(rng, SOURCE_WEIGHTS);
  return buildEvent({
    eventType: weightedPick(rng, profile.mix),
    timestamp,
    rng,
    sourceIp: profile.ip,
  });
}

/**
 * Relative event density by hour of day. Overnight is quiet, business hours
 * are busy — a flat distribution is the tell of fabricated data.
 */
function diurnalWeight(hour: number): number {
  if (hour >= 9 && hour <= 18) return 1.6;
  if (hour >= 7 && hour < 9) return 1.1;
  if (hour > 18 && hour <= 22) return 0.9;
  return 0.35;
}

/**
 * Assigns a lifecycle status based on age. Anything older than a couple of
 * hours has plausibly been worked; recent detections stay in the queue.
 */
function triageStatus(rng: Rng, ageMs: number): EventStatus {
  const ageHours = ageMs / 3_600_000;
  if (ageHours < 1) return 'new';
  if (ageHours < 2) {
    return weightedPick(rng, [
      ['new', 5],
      ['investigating', 3],
      ['resolved', 2],
    ]);
  }
  if (ageHours < 6) {
    return weightedPick(rng, [
      ['resolved', 6],
      ['investigating', 2],
      ['blocked', 2],
    ]);
  }
  return weightedPick(rng, [
    ['resolved', 8],
    ['blocked', 2],
  ]);
}

/** Builds the retained history window ending at `now`. */
export function generateBackfill(now: number): SecurityEvent[] {
  const rng = createRng(BACKFILL_SEED);
  const events: SecurityEvent[] = [];
  const recentWindowStart = now - HISTORY_WINDOW_MS;

  let t = now - RETENTION_WINDOW_MS;
  while (t < now) {
    const weight = diurnalWeight(new Date(t).getHours());
    // Base cadence ~30s, scaled by how busy the hour is, then thinned for
    // aged data so a week of history stays affordable.
    const density = t < recentWindowStart ? AGED_DENSITY_DIVISOR : 1;
    t += Math.max(4000, Math.round((30_000 / weight) * (0.4 + rng() * 1.4) * density));
    if (t >= now) break;

    const event = createAmbientEvent(rng, t);
    event.status = triageStatus(rng, now - t);
    events.push(event);
  }

  // Attack bursts. Each scenario fires once inside the last 24 hours (so the
  // dashboard opens on recent, recognizable activity) and again earlier in the
  // week to give the 7-day view real peaks rather than a flat line.
  const recentOffsetHours = [21.5, 16.2, 11.4, 6.1, 2.3, 0.6];
  const historicOffsetHours = [156, 132, 108, 91, 67, 44];
  ALL_SCENARIOS.forEach((scenario, index) => {
    const offsets = [recentOffsetHours[index] ?? 3, historicOffsetHours[index] ?? 72];
    for (const offsetHours of offsets) {
      const startTime = now - offsetHours * 3_600_000;
      for (const event of materializeScenario(scenario, startTime, rng)) {
        event.status = triageStatus(rng, now - event.timestamp);
        events.push(event);
      }
    }
  });

  return events.sort((a, b) => a.timestamp - b.timestamp);
}
