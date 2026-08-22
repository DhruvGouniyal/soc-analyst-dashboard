import { useCallback, useMemo, useState } from 'react';
import { EMPTY_FILTERS, filterEvents, hasActiveFilters, sortEvents } from '@/services/eventStore';
import type {
  EventFilters,
  EventStatus,
  EventType,
  SecurityEvent,
  SortDirection,
  SortKey,
  Severity,
} from '@/types/security';

export interface UseEventFiltersResult {
  filters: EventFilters;
  /** Filtered and sorted, ready to render. */
  results: SecurityEvent[];
  /** Count before filtering, for the "showing X of Y" line. */
  totalCount: number;
  active: boolean;
  sortKey: SortKey;
  sortDirection: SortDirection;
  setQuery: (query: string) => void;
  toggleSeverity: (severity: Severity) => void;
  setSeverities: (severities: Severity[]) => void;
  toggleEventType: (eventType: EventType) => void;
  toggleHost: (host: string) => void;
  toggleStatus: (status: EventStatus) => void;
  setSort: (key: SortKey) => void;
  clear: () => void;
}

/** Toggles a value in a filter array without mutating it. */
function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}

/**
 * Filter and sort state for an event collection.
 *
 * Kept as a hook rather than context so the dashboard feed and a future Alerts
 * page can each hold independent filter state over the same event set.
 */
export function useEventFilters(events: SecurityEvent[]): UseEventFiltersResult {
  const [filters, setFilters] = useState<EventFilters>(EMPTY_FILTERS);
  /**
   * Key and direction share one state object so the toggle can be expressed as
   * a single pure updater. Nesting `setSortDirection` inside a `setSortKey`
   * updater would break under StrictMode, which double-invokes updaters — the
   * direction would flip twice and appear not to change at all.
   */
  const [sort, setSort_] = useState<{ key: SortKey; direction: SortDirection }>({
    key: 'timestamp',
    direction: 'desc',
  });

  const results = useMemo(
    () => sortEvents(filterEvents(events, filters), sort.key, sort.direction),
    [events, filters, sort],
  );

  const setQuery = useCallback((query: string) => {
    setFilters((current) => ({ ...current, query }));
  }, []);

  const toggleSeverity = useCallback((severity: Severity) => {
    setFilters((current) => ({ ...current, severities: toggle(current.severities, severity) }));
  }, []);

  const setSeverities = useCallback((severities: Severity[]) => {
    setFilters((current) => ({ ...current, severities }));
  }, []);

  const toggleEventType = useCallback((eventType: EventType) => {
    setFilters((current) => ({ ...current, eventTypes: toggle(current.eventTypes, eventType) }));
  }, []);

  const toggleHost = useCallback((host: string) => {
    setFilters((current) => ({ ...current, hosts: toggle(current.hosts, host) }));
  }, []);

  const toggleStatus = useCallback((status: EventStatus) => {
    setFilters((current) => ({ ...current, statuses: toggle(current.statuses, status) }));
  }, []);

  /** Re-selecting the active column flips direction, as in a data grid. */
  const setSort = useCallback((key: SortKey) => {
    setSort_((current) =>
      current.key === key
        ? { key, direction: current.direction === 'desc' ? 'asc' : 'desc' }
        : { key, direction: 'desc' },
    );
  }, []);

  const clear = useCallback(() => setFilters(EMPTY_FILTERS), []);

  return {
    filters,
    results,
    totalCount: events.length,
    active: hasActiveFilters(filters),
    sortKey: sort.key,
    sortDirection: sort.direction,
    setQuery,
    toggleSeverity,
    setSeverities,
    toggleEventType,
    toggleHost,
    toggleStatus,
    setSort,
    clear,
  };
}
