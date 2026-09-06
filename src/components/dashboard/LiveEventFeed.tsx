import { ArrowDownWideNarrow, Inbox, Pause } from 'lucide-react';
import { useMemo } from 'react';
import { cn } from '@/lib/cn';
import { countBySeverity } from '@/services/metrics';
import type { UseEventFiltersResult } from '@/hooks/useEventFilters';
import type { Host, SecurityEvent } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { Button } from '@/components/ui/Button';
import { EmptyState, SkeletonRows } from '@/components/ui/States';
import { EventFilterBar } from './EventFilterBar';
import { EventRow } from './EventRow';

/**
 * Rows rendered at once. The store retains thousands of events; painting them
 * all would cost far more than it communicates, and the feed is a "most recent
 * matching" view by nature. Search narrows the full set, not just this slice.
 */
const RENDER_LIMIT = 150;

interface LiveEventFeedProps {
  filters: UseEventFiltersResult;
  hosts: Host[];
  loading: boolean;
  selectedId: string | null;
  onSelect: (event: SecurityEvent) => void;
  /** All events, pre-filter — used for the chip counts. */
  allEvents: SecurityEvent[];
  now: number;
  paused: boolean;
  bufferedCount: number;
  onResume: () => void;
  /**
   * Height constraint, supplied by the parent. The feed always scrolls
   * internally, so whoever places it decides how tall it may get: the dashboard
   * caps it so the grid row stays sane, the full-page triage view fills the
   * viewport. Without a definite height the panel grows to fit every row.
   */
  className?: string;
}

export function LiveEventFeed({
  filters,
  hosts,
  loading,
  selectedId,
  onSelect,
  allEvents,
  now,
  paused,
  bufferedCount,
  onResume,
  className = 'min-h-[320px]',
}: LiveEventFeedProps) {
  const counts = useMemo(() => countBySeverity(allEvents), [allEvents]);

  /*
   * Rows are memoized, but `now` ticks every 2s, which invalidated all 150 of
   * them on every tick and made the feed the most expensive thing on the page.
   * Relative ages are rendered at minute granularity, so a 10s clock is
   * indistinguishable on screen and cuts row re-renders by 5x.
   */
  const rowNow = Math.floor(now / 10_000) * 10_000;
  const { results, totalCount, sortKey, setSort, sortDirection, active, clear } = filters;
  const visible = results.slice(0, RENDER_LIMIT);

  return (
    <Panel
      title="Live Security Events"
      meta={
        active
          ? `${results.length.toLocaleString('en-US')} of ${totalCount.toLocaleString('en-US')}`
          : `${totalCount.toLocaleString('en-US')} retained`
      }
      actions={
        <Button
          variant="ghost"
          onClick={() => setSort(sortKey === 'timestamp' ? 'severity' : 'timestamp')}
          title={`Sorted by ${sortKey === 'timestamp' ? 'time' : 'severity'} (${sortDirection}). Click to change.`}
        >
          <ArrowDownWideNarrow className="h-3 w-3" />
          {sortKey === 'timestamp' ? 'Time' : 'Severity'}
        </Button>
      }
      flush
      className={className}
    >
      <div className="flex h-full min-h-0 flex-col">
        <EventFilterBar filters={filters} counts={counts} hosts={hosts} />

        {paused && bufferedCount > 0 ? (
          <button
            type="button"
            onClick={onResume}
            className="flex items-center justify-center gap-1.5 border-b border-accent/30 bg-accent/10 py-1.5 text-[11px] text-accent hover:bg-accent/15"
          >
            <Pause className="h-3 w-3" />
            {bufferedCount} new event{bufferedCount === 1 ? '' : 's'} held — resume to view
          </button>
        ) : null}

        <div className="min-h-0 flex-1 overflow-y-auto">
          {loading ? (
            <SkeletonRows rows={6} />
          ) : visible.length === 0 ? (
            <EmptyState
              icon={<Inbox className="h-5 w-5" />}
              title={active ? 'No events match these filters' : 'No security events'}
              description={
                active
                  ? 'Try widening the severity selection or clearing the search query.'
                  : 'The detection engine has not reported any activity in the retained window.'
              }
              action={
                active ? (
                  <Button variant="default" onClick={clear}>
                    Clear filters
                  </Button>
                ) : null
              }
            />
          ) : (
            <>
              {visible.map((event) => (
                <EventRow
                  key={event.id}
                  event={event}
                  selected={event.id === selectedId}
                  onSelect={onSelect}
                  now={rowNow}
                />
              ))}
              {results.length > RENDER_LIMIT ? (
                <div
                  className={cn(
                    'border-t border-[var(--separator)] px-3 py-2 text-center text-[10.5px] text-fg-dim',
                  )}
                >
                  Showing the {RENDER_LIMIT} most recent of{' '}
                  {results.length.toLocaleString('en-US')} matches — refine filters to narrow.
                </div>
              ) : null}
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}
