/**
 * Pure event-collection operations.
 *
 * Deliberately framework-free so filtering and retention can be unit tested,
 * reused by a future Alerts page, or moved server-side without dragging React
 * along.
 */
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_META } from '@/config/severity';
import type {
  EventFilters,
  SecurityEvent,
  SortDirection,
  SortKey,
} from '@/types/security';

/**
 * Upper bound on retained events. The seeded backfill produces roughly 5.5k;
 * this leaves headroom for a long live session without unbounded growth.
 */
export const MAX_RETAINED_EVENTS = 12_000;

/**
 * How far into the (newest-first) collection to look when checking whether an
 * arriving event is one we already hold.
 *
 * A real backend replays recent events when a dropped WebSocket reconnects, so
 * the same detection can arrive twice. Duplicates are never merely cosmetic
 * here: the feed keys rows by `id`, and the KPI, risk-score, and attack-source
 * calculations all count events, so a duplicate inflates every number on the
 * dashboard. Replayed events are by definition recent, so scanning the head is
 * sufficient and keeps this O(1) rather than O(n) per arrival.
 */
const DEDUPE_SCAN_DEPTH = 500;

export const EMPTY_FILTERS: EventFilters = {
  severities: [],
  query: '',
  eventTypes: [],
  hosts: [],
  statuses: [],
};

/**
 * Prepends a new event and trims the oldest past the cap.
 *
 * Events are held newest-first: the feed reads from the head, so the common
 * path is O(1) and never re-sorts the full collection on every arrival.
 */
export function addEvent(events: SecurityEvent[], incoming: SecurityEvent): SecurityEvent[] {
  for (let i = 0; i < Math.min(events.length, DEDUPE_SCAN_DEPTH); i += 1) {
    if (events[i]!.id === incoming.id) return events;
  }
  const next = [incoming, ...events];
  return next.length > MAX_RETAINED_EVENTS ? next.slice(0, MAX_RETAINED_EVENTS) : next;
}

/**
 * Normalizes a provider snapshot into the newest-first invariant, dropping
 * duplicate ids.
 *
 * Deduping here as well as in `addEvent` is not redundant: while the feed is
 * paused, arriving events bypass `addEvent` entirely and are buffered, then
 * flushed through this function on resume. That flush is exactly where a
 * reconnect replay would otherwise introduce duplicates.
 */
export function initializeEvents(events: SecurityEvent[]): SecurityEvent[] {
  const seen = new Set<string>();
  const unique: SecurityEvent[] = [];
  for (const event of events) {
    if (seen.has(event.id)) continue;
    seen.add(event.id);
    unique.push(event);
  }
  unique.sort((a, b) => b.timestamp - a.timestamp);
  return unique.length > MAX_RETAINED_EVENTS ? unique.slice(0, MAX_RETAINED_EVENTS) : unique;
}

/** Applies an analyst action to one event, returning a new collection. */
export function updateEventStatus(
  events: SecurityEvent[],
  id: string,
  status: SecurityEvent['status'],
): SecurityEvent[] {
  return events.map((event) => (event.id === id ? { ...event, status } : event));
}

/**
 * Blocking an IP is a source-wide action, not a per-alert one: every open
 * event from that origin moves to `blocked` so the queue reflects reality.
 */
export function blockSourceIp(events: SecurityEvent[], ip: string): SecurityEvent[] {
  return events.map((event) =>
    event.sourceIp === ip && (event.status === 'new' || event.status === 'investigating')
      ? { ...event, status: 'blocked' }
      : event,
  );
}

/** Free-text match across the fields an analyst would actually search by. */
function matchesQuery(event: SecurityEvent, query: string): boolean {
  const meta = EVENT_TYPES[event.eventType];
  const haystack = [
    event.sourceIp,
    event.destinationIp,
    event.description,
    event.host,
    event.eventType,
    meta.label,
    event.mitreTechnique ?? '',
    event.protocol,
    String(event.destinationPort ?? ''),
  ]
    .join(' ')
    .toLowerCase();
  return haystack.includes(query);
}

/** Applies all active filters. Empty arrays mean "no constraint". */
export function filterEvents(events: SecurityEvent[], filters: EventFilters): SecurityEvent[] {
  const query = filters.query.trim().toLowerCase();
  const hasQuery = query.length > 0;

  return events.filter((event) => {
    if (filters.severities.length > 0 && !filters.severities.includes(event.severity)) return false;
    if (filters.eventTypes.length > 0 && !filters.eventTypes.includes(event.eventType)) return false;
    if (filters.hosts.length > 0 && !filters.hosts.includes(event.host)) return false;
    if (filters.statuses.length > 0 && !filters.statuses.includes(event.status)) return false;
    if (hasQuery && !matchesQuery(event, query)) return false;
    return true;
  });
}

/**
 * Sorts a filtered slice. Severity sorts break ties by recency so the most
 * urgent *and* most recent alert surfaces first.
 */
export function sortEvents(
  events: SecurityEvent[],
  key: SortKey,
  direction: SortDirection,
): SecurityEvent[] {
  const sign = direction === 'desc' ? 1 : -1;
  return [...events].sort((a, b) => {
    if (key === 'severity') {
      const delta = SEVERITY_META[a.severity].rank - SEVERITY_META[b.severity].rank;
      if (delta !== 0) return delta * sign;
      return b.timestamp - a.timestamp;
    }
    return (b.timestamp - a.timestamp) * sign;
  });
}

/** True when any constraint is active — drives the "clear filters" affordance. */
export function hasActiveFilters(filters: EventFilters): boolean {
  return (
    filters.severities.length > 0 ||
    filters.eventTypes.length > 0 ||
    filters.hosts.length > 0 ||
    filters.statuses.length > 0 ||
    filters.query.trim().length > 0
  );
}
