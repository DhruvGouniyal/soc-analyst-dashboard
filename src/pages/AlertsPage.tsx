import { useCallback, useMemo, useState } from 'react';
import { useClock } from '@/hooks/useClock';
import { useEventFilters } from '@/hooks/useEventFilters';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import type { SecurityEvent } from '@/types/security';
import { AlertDetailPanel } from '@/components/dashboard/AlertDetailPanel';
import { LiveEventFeed } from '@/components/dashboard/LiveEventFeed';

/**
 * Full-height triage queue.
 *
 * Reuses the dashboard's feed and detail components verbatim — the filter hook
 * is instantiated separately, so narrowing the queue here does not disturb the
 * dashboard's own filter state.
 */
export function AlertsPage() {
  const { events, hosts, loading, paused, setPaused, bufferedCount, applyAction } =
    useSecurityFeed();
  const now = useClock(2000);
  const filters = useEventFilters(events);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedId) ?? null,
    [events, selectedId],
  );

  const handleSelect = useCallback(
    (event: SecurityEvent) => setSelectedId((current) => (current === event.id ? null : event.id)),
    [],
  );

  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1 p-3">
        <LiveEventFeed
          filters={filters}
          hosts={hosts}
          loading={loading}
          selectedId={selectedId}
          onSelect={handleSelect}
          allEvents={events}
          now={now}
          paused={paused}
          bufferedCount={bufferedCount}
          onResume={() => setPaused(false)}
        />
      </div>

      <AlertDetailPanel
        event={selectedEvent}
        events={events}
        onClose={() => setSelectedId(null)}
        onAction={applyAction}
        now={now}
      />
    </div>
  );
}
