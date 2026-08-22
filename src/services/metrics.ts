/**
 * Derived metrics.
 *
 * Everything the dashboard displays as a number is computed here from the
 * event set — no component holds a literal count. That is what makes the KPIs
 * respond to live events and to analyst actions (resolving an alert lowers the
 * queue and raises the security score) instead of being decoration.
 */
import { VICTIM_IP } from '@/data/topology';
import type {
  ActivityBucket,
  AttackSource,
  EventType,
  Host,
  HostWithRisk,
  SecurityEvent,
  SecurityKpis,
  Severity,
  TimeRangeKey,
} from '@/types/security';
import { computeAssetRisk, computeSourceRisk, riskToSeverity } from './riskEngine';
import { dayAndTime, shortTime } from './time';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/** Window and bucket geometry for each selectable chart range. */
export const TIME_RANGES: Record<
  TimeRangeKey,
  { key: TimeRangeKey; label: string; windowMs: number; bucketMs: number; labelFor: (t: number) => string }
> = {
  '1h': { key: '1h', label: 'Last 1 hour', windowMs: HOUR_MS, bucketMs: 3 * 60_000, labelFor: shortTime },
  '6h': { key: '6h', label: 'Last 6 hours', windowMs: 6 * HOUR_MS, bucketMs: 15 * 60_000, labelFor: shortTime },
  '24h': { key: '24h', label: 'Last 24 hours', windowMs: DAY_MS, bucketMs: HOUR_MS, labelFor: shortTime },
  '7d': { key: '7d', label: 'Last 7 days', windowMs: 7 * DAY_MS, bucketMs: 6 * HOUR_MS, labelFor: dayAndTime },
};

export const TIME_RANGE_KEYS = Object.keys(TIME_RANGES) as TimeRangeKey[];

/** Unresolved events represent live exposure; closed ones do not. */
function isOpen(event: SecurityEvent): boolean {
  return event.status === 'new' || event.status === 'investigating';
}

function inWindow(event: SecurityEvent, from: number, to: number): boolean {
  return event.timestamp >= from && event.timestamp <= to;
}

/**
 * Headline counters.
 *
 * Severity counts are the *open triage queue* over the last 24 hours rather
 * than raw lifetime totals — that is the number an analyst actually works, and
 * it moves when alerts are actioned.
 */
export function computeKpis(events: SecurityEvent[], now = Date.now()): SecurityKpis {
  const dayAgo = now - DAY_MS;
  const hourAgo = now - HOUR_MS;
  const twoHoursAgo = now - 2 * HOUR_MS;

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let totalEvents = 0;
  let criticalThisHour = 0;
  let criticalPrevHour = 0;
  let highThisHour = 0;
  let highPrevHour = 0;

  const threatSources = new Set<string>();
  const unacknowledgedSources = new Set<string>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    totalEvents += 1;

    if (isOpen(event)) {
      counts[event.severity] += 1;
      if (event.severity === 'critical' || event.severity === 'high') {
        threatSources.add(event.sourceIp);
        if (event.status === 'new') unacknowledgedSources.add(event.sourceIp);
      }
    }

    if (event.severity === 'critical') {
      if (event.timestamp >= hourAgo) criticalThisHour += 1;
      else if (event.timestamp >= twoHoursAgo) criticalPrevHour += 1;
    }
    if (event.severity === 'high') {
      if (event.timestamp >= hourAgo) highThisHour += 1;
      else if (event.timestamp >= twoHoursAgo) highPrevHour += 1;
    }
  }

  return {
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    totalEvents,
    activeThreats: threatSources.size,
    threatsRequiringAttention: unacknowledgedSources.size,
    criticalDeltaLastHour: criticalThisHour - criticalPrevHour,
    highDeltaPercent:
      highPrevHour === 0
        ? highThisHour > 0
          ? 100
          : 0
        : Math.round(((highThisHour - highPrevHour) / highPrevHour) * 100),
  };
}

/**
 * Buckets events for the activity chart, split by severity so the stack shows
 * composition rather than just volume. Empty buckets are emitted explicitly —
 * a gap in the series should read as "no activity", not as missing data.
 */
export function bucketActivity(
  events: SecurityEvent[],
  range: TimeRangeKey,
  now = Date.now(),
): ActivityBucket[] {
  const { windowMs, bucketMs, labelFor } = TIME_RANGES[range];
  const bucketCount = Math.ceil(windowMs / bucketMs);
  // Anchor buckets to the bucket grid so labels land on round times.
  const end = Math.ceil(now / bucketMs) * bucketMs;
  const start = end - bucketCount * bucketMs;

  const buckets: ActivityBucket[] = Array.from({ length: bucketCount }, (_, i) => {
    const t = start + i * bucketMs;
    return { t, label: labelFor(t), critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  });

  for (const event of events) {
    if (event.timestamp < start || event.timestamp >= end) continue;
    const index = Math.floor((event.timestamp - start) / bucketMs);
    const bucket = buckets[index];
    if (!bucket) continue;
    bucket[event.severity] += 1;
    bucket.total += 1;
  }

  return buckets;
}

/**
 * Most active attacking IPs, ranked by risk rather than raw volume so a single
 * critical detection outranks a flood of benign connections.
 *
 * The monitored host's own IP is excluded: this panel answers "who is hitting
 * us", and the victim originating outbound traffic is a different question
 * (surfaced instead as exfiltration events).
 */
export function computeTopSources(
  events: SecurityEvent[],
  limit = 5,
  now = Date.now(),
): AttackSource[] {
  const dayAgo = now - DAY_MS;
  const grouped = new Map<
    string,
    { events: SecurityEvent[]; types: Map<EventType, number> }
  >();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    if (event.sourceIp === VICTIM_IP) continue;

    let entry = grouped.get(event.sourceIp);
    if (!entry) {
      entry = { events: [], types: new Map() };
      grouped.set(event.sourceIp, entry);
    }
    entry.events.push(event);
    entry.types.set(event.eventType, (entry.types.get(event.eventType) ?? 0) + 1);
  }

  const sources: AttackSource[] = [];
  for (const [ip, entry] of grouped) {
    const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    let firstSeen = Infinity;
    let lastSeen = 0;
    for (const event of entry.events) {
      severityCounts[event.severity] += 1;
      if (event.timestamp < firstSeen) firstSeen = event.timestamp;
      if (event.timestamp > lastSeen) lastSeen = event.timestamp;
    }

    // Label the source by whichever detection it triggers most often.
    let dominantThreat: EventType = 'new_connection';
    let best = -1;
    for (const [type, count] of entry.types) {
      if (count > best) {
        best = count;
        dominantThreat = type;
      }
    }

    sources.push({
      ip,
      eventCount: entry.events.length,
      severityCounts,
      dominantThreat,
      firstSeen,
      lastSeen,
      riskScore: computeSourceRisk(entry.events),
    });
  }

  return sources
    .sort((a, b) => b.riskScore - a.riskScore || b.eventCount - a.eventCount)
    .slice(0, limit);
}

/** Attaches event-derived risk to each host so the table isn't static. */
export function computeHostRisk(
  hosts: Host[],
  events: SecurityEvent[],
  now = Date.now(),
): HostWithRisk[] {
  const dayAgo = now - DAY_MS;
  const byHost = new Map<string, SecurityEvent[]>();

  for (const event of events) {
    if (!inWindow(event, dayAgo, now)) continue;
    const list = byHost.get(event.host);
    if (list) list.push(event);
    else byHost.set(event.host, [event]);
  }

  return hosts.map((host) => {
    const hostEvents = byHost.get(host.id) ?? [];
    const riskScore = computeAssetRisk(hostEvents);
    return {
      ...host,
      riskScore,
      riskLevel: riskToSeverity(riskScore),
      eventCount: hostEvents.length,
    };
  });
}

/** Event totals by severity, used for the filter chips' counts. */
export function countBySeverity(events: SecurityEvent[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const event of events) counts[event.severity] += 1;
  return counts;
}
