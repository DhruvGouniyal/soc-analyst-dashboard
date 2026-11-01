/**
 * Views derived from the live event stream.
 *
 * Incidents, network flows, and threat indicators are not stored — they are
 * projections of the same `SecurityEvent[]` the dashboard already holds. Keeping
 * the derivation here (rather than inventing a parallel mock dataset) means the
 * Incidents, Network, and Threat Intelligence pages stay consistent with the
 * feed, the KPIs, and each other: block a source on one page and it changes
 * everywhere, because they all read from one truth.
 */
import { EVENT_TYPES } from '@/config/eventTypes';
import { getTechnique, type MitreTechnique } from '@/config/mitre';
import { SEVERITY_META } from '@/config/severity';
import { VICTIM_IP } from '@/data/topology';
import { computeSourceRisk, riskToSeverity } from '@/services/riskEngine';
import type { EventType, Protocol, SecurityEvent, Severity } from '@/types/security';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Worst (lowest-rank) severity in a list; `low` for an empty list. */
function maxSeverity(severities: Severity[]): Severity {
  return severities.reduce<Severity>(
    (worst, s) => (SEVERITY_META[s].rank < SEVERITY_META[worst].rank ? s : worst),
    'low',
  );
}

/** Deterministic 32-bit hash, so synthesized figures are stable across renders. */
function hashString(input: string): number {
  let h = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function inWindow(event: SecurityEvent, from: number, to: number): boolean {
  return event.timestamp >= from && event.timestamp <= to;
}

function isOpen(event: SecurityEvent): boolean {
  return event.status === 'new' || event.status === 'investigating';
}

// --------------------------------------------------------------- Incidents

export type IncidentStatus = 'active' | 'contained' | 'resolved';

export interface Incident {
  id: string;
  title: string;
  sourceIp: string;
  severity: Severity;
  status: IncidentStatus;
  eventCount: number;
  firstSeen: number;
  lastSeen: number;
  /** Distinct MITRE techniques observed across the chain. */
  techniques: MitreTechnique[];
  /** Distinct detection types, most severe first. */
  stages: EventType[];
  hosts: string[];
  riskScore: number;
  narrative: string;
}

const INCIDENT_TITLES: Partial<Record<EventType, string>> = {
  ssh_brute_force: 'SSH brute-force campaign',
  ssh_failed_auth: 'Repeated SSH authentication failures',
  suspicious_login: 'Credential-guessing activity',
  port_scan: 'Network reconnaissance',
  web_attack: 'Web application attack',
  privilege_escalation: 'Privilege-escalation attempt',
  data_exfiltration: 'Suspected data exfiltration',
  malware_signature: 'Malware delivery attempt',
};

/**
 * Correlates events into incidents, grouping by source IP over the last 24h.
 * Only sources that produced a high/critical detection or a sustained burst
 * surface — a single benign connection is not an incident.
 */
export function deriveIncidents(events: SecurityEvent[], now = Date.now()): Incident[] {
  const dayAgo = now - DAY_MS;
  const bySource = new Map<string, SecurityEvent[]>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    // Victim-originated events are outbound noise, not an inbound campaign.
    if (event.sourceIp === VICTIM_IP) continue;
    const list = bySource.get(event.sourceIp);
    if (list) list.push(event);
    else bySource.set(event.sourceIp, [event]);
  }

  const incidents: Incident[] = [];
  for (const [sourceIp, group] of bySource) {
    const notable = group.some((e) => e.severity === 'critical' || e.severity === 'high');
    if (!notable && group.length < 8) continue;

    const severities = group.map((e) => e.severity);
    const severity = maxSeverity(severities);
    const timestamps = group.map((e) => e.timestamp);
    const firstSeen = Math.min(...timestamps);
    const lastSeen = Math.max(...timestamps);

    // Stages ordered by severity so the chain reads worst-first.
    const typeCounts = new Map<EventType, number>();
    for (const e of group) typeCounts.set(e.eventType, (typeCounts.get(e.eventType) ?? 0) + 1);
    const stages = [...typeCounts.keys()].sort(
      (a, b) => SEVERITY_META[EVENT_TYPES[a].defaultSeverity].rank - SEVERITY_META[EVENT_TYPES[b].defaultSeverity].rank,
    );

    const techniques = [...new Set(group.map((e) => e.mitreTechnique).filter(Boolean))]
      .map((id) => getTechnique(id))
      .filter((t): t is MitreTechnique => t !== null);

    const hosts = [...new Set(group.map((e) => e.host))];

    // Status reflects how far the queue has been worked for this source.
    const anyOpen = group.some(isOpen);
    const anyBlocked = group.some((e) => e.status === 'blocked');
    const status: IncidentStatus = anyOpen ? 'active' : anyBlocked ? 'contained' : 'resolved';

    const dominant = stages[0] ?? group[0]!.eventType;
    const title = INCIDENT_TITLES[dominant] ?? 'Suspicious activity';

    incidents.push({
      id: `inc-${hashString(sourceIp).toString(36)}`,
      title,
      sourceIp,
      severity,
      status,
      eventCount: group.length,
      firstSeen,
      lastSeen,
      techniques,
      stages,
      hosts,
      riskScore: computeSourceRisk(group),
      narrative: buildNarrative(sourceIp, group.length, stages, techniques),
    });
  }

  return incidents.sort(
    (a, b) => SEVERITY_META[a.severity].rank - SEVERITY_META[b.severity].rank || b.lastSeen - a.lastSeen,
  );
}

function buildNarrative(
  sourceIp: string,
  count: number,
  stages: EventType[],
  techniques: MitreTechnique[],
): string {
  const stageLabels = stages.slice(0, 3).map((t) => EVENT_TYPES[t].shortLabel.toLowerCase());
  const chain = stageLabels.length > 1 ? stageLabels.join(' → ') : stageLabels[0] ?? 'activity';
  const tech = techniques.length ? ` Mapped to ${techniques.map((t) => t.id).join(', ')}.` : '';
  return `${count} correlated events from ${sourceIp}, progressing through ${chain}.${tech}`;
}

// ---------------------------------------------------------------- Network

export type FlowState = 'established' | 'attempted' | 'blocked';

export interface NetworkFlow {
  id: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number | null;
  protocol: Protocol;
  count: number;
  /** Synthesized from volume — no real byte counts exist in auth data. */
  bytes: number;
  lastSeen: number;
  severity: Severity;
  state: FlowState;
}

export interface TopTalker {
  ip: string;
  flows: number;
  events: number;
  bytes: number;
  severity: Severity;
}

/** Aggregates events into directional flows keyed by src→dst:port/proto. */
export function deriveNetworkFlows(
  events: SecurityEvent[],
  now = Date.now(),
): { flows: NetworkFlow[]; talkers: TopTalker[] } {
  const dayAgo = now - DAY_MS;
  const grouped = new Map<string, SecurityEvent[]>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    const key = `${event.sourceIp}|${event.destinationIp}|${event.destinationPort ?? '-'}|${event.protocol}`;
    const list = grouped.get(key);
    if (list) list.push(event);
    else grouped.set(key, [event]);
  }

  const flows: NetworkFlow[] = [];
  for (const [key, group] of grouped) {
    const first = group[0]!;
    const severity = maxSeverity(group.map((e) => e.severity));
    const anyBlocked = group.some((e) => e.status === 'blocked');
    const anyOpen = group.some(isOpen);
    const state: FlowState = anyBlocked ? 'blocked' : anyOpen ? 'attempted' : 'established';
    // Plausible byte volume: scales with event count, deterministic per flow.
    const bytes = group.length * (1200 + (hashString(key) % 8800));

    flows.push({
      id: `flow-${hashString(key).toString(36)}`,
      sourceIp: first.sourceIp,
      destinationIp: first.destinationIp,
      destinationPort: first.destinationPort,
      protocol: first.protocol,
      count: group.length,
      bytes,
      lastSeen: Math.max(...group.map((e) => e.timestamp)),
      severity,
      state,
    });
  }

  flows.sort(
    (a, b) => SEVERITY_META[a.severity].rank - SEVERITY_META[b.severity].rank || b.count - a.count,
  );

  // Top talkers: per-source rollup across all its flows.
  const byTalker = new Map<string, TopTalker>();
  for (const flow of flows) {
    const existing = byTalker.get(flow.sourceIp);
    if (existing) {
      existing.flows += 1;
      existing.events += flow.count;
      existing.bytes += flow.bytes;
      if (SEVERITY_META[flow.severity].rank < SEVERITY_META[existing.severity].rank) {
        existing.severity = flow.severity;
      }
    } else {
      byTalker.set(flow.sourceIp, {
        ip: flow.sourceIp,
        flows: 1,
        events: flow.count,
        bytes: flow.bytes,
        severity: flow.severity,
      });
    }
  }
  const talkers = [...byTalker.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 6);

  return { flows, talkers };
}

// -------------------------------------------------------- Threat Intel

export type IndicatorType = 'ip-source' | 'ip-destination';

export interface Indicator {
  value: string;
  type: IndicatorType;
  severity: Severity;
  /** 0–100 reputation risk. */
  riskScore: number;
  confidence: number;
  eventCount: number;
  firstSeen: number;
  lastSeen: number;
  dominantThreat: EventType;
  technique: MitreTechnique | null;
}

export interface TechniqueCoverage {
  technique: MitreTechnique;
  count: number;
  severity: Severity;
  lastSeen: number;
}

/**
 * Indicators of compromise observed in the window: attacking source IPs and
 * any external destinations the victim reached out to (exfil candidates).
 */
export function deriveIndicators(events: SecurityEvent[], now = Date.now()): Indicator[] {
  const dayAgo = now - DAY_MS;
  const sources = new Map<string, SecurityEvent[]>();
  const destinations = new Map<string, SecurityEvent[]>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    if (event.sourceIp !== VICTIM_IP) {
      const list = sources.get(event.sourceIp);
      if (list) list.push(event);
      else sources.set(event.sourceIp, [event]);
    }
    // External destinations (victim reaching out) are exfil/C2 candidates.
    if (event.sourceIp === VICTIM_IP && event.destinationIp !== VICTIM_IP) {
      const list = destinations.get(event.destinationIp);
      if (list) list.push(event);
      else destinations.set(event.destinationIp, [event]);
    }
  }

  const indicators: Indicator[] = [];
  const build = (value: string, group: SecurityEvent[], type: IndicatorType): Indicator => {
    const typeCounts = new Map<EventType, number>();
    for (const e of group) typeCounts.set(e.eventType, (typeCounts.get(e.eventType) ?? 0) + 1);
    const dominantThreat = [...typeCounts.entries()].sort((a, b) => b[1] - a[1])[0]![0];
    const risk = computeSourceRisk(group);
    return {
      value,
      type,
      severity: riskToSeverity(risk),
      riskScore: risk,
      confidence: Math.round(group.reduce((s, e) => s + e.confidence, 0) / group.length),
      eventCount: group.length,
      firstSeen: Math.min(...group.map((e) => e.timestamp)),
      lastSeen: Math.max(...group.map((e) => e.timestamp)),
      dominantThreat,
      technique: getTechnique(EVENT_TYPES[dominantThreat].mitre),
    };
  };

  for (const [ip, group] of sources) indicators.push(build(ip, group, 'ip-source'));
  for (const [ip, group] of destinations) indicators.push(build(ip, group, 'ip-destination'));

  return indicators.sort(
    (a, b) => SEVERITY_META[a.severity].rank - SEVERITY_META[b.severity].rank || b.riskScore - a.riskScore,
  );
}

/** Per-technique MITRE ATT&CK coverage, for the intel heat list. */
export function deriveMitreCoverage(events: SecurityEvent[], now = Date.now()): TechniqueCoverage[] {
  const dayAgo = now - DAY_MS;
  const byTechnique = new Map<string, { count: number; severities: Severity[]; lastSeen: number }>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now) || !event.mitreTechnique) continue;
    const entry = byTechnique.get(event.mitreTechnique);
    if (entry) {
      entry.count += 1;
      entry.severities.push(event.severity);
      entry.lastSeen = Math.max(entry.lastSeen, event.timestamp);
    } else {
      byTechnique.set(event.mitreTechnique, {
        count: 1,
        severities: [event.severity],
        lastSeen: event.timestamp,
      });
    }
  }

  const coverage: TechniqueCoverage[] = [];
  for (const [id, entry] of byTechnique) {
    const technique = getTechnique(id);
    if (!technique) continue;
    coverage.push({
      technique,
      count: entry.count,
      severity: maxSeverity(entry.severities),
      lastSeen: entry.lastSeen,
    });
  }

  return coverage.sort((a, b) => b.count - a.count);
}

/** Human-readable byte size, e.g. `2.4 MB`. */
export function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1000) return `${(bytes / 1000).toFixed(1)} KB`;
  return `${bytes} B`;
}
