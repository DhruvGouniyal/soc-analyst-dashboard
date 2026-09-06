import { ArrowRight } from 'lucide-react';
import { memo } from 'react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { relativeTime } from '@/services/time';
import type { SecurityEvent } from '@/types/security';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { StatusBadge } from '@/components/ui/StatusBadge';

/** Events younger than this get the arrival tint. */
const ENTER_WINDOW_MS = 2500;

interface EventRowProps {
  event: SecurityEvent;
  selected: boolean;
  onSelect: (event: SecurityEvent) => void;
  now: number;
}

/**
 * One line in the live feed.
 *
 * Memoized because the feed re-renders whenever any event arrives; without it
 * every visible row would reconcile on each tick.
 */
export const EventRow = memo(function EventRow({ event, selected, onSelect, now }: EventRowProps) {
  const meta = EVENT_TYPES[event.eventType];
  const styles = SEVERITY_STYLES[event.severity];
  const isNew = now - event.timestamp < ENTER_WINDOW_MS;
  const isClosed = event.status === 'resolved' || event.status === 'blocked';

  return (
    <button
      type="button"
      onClick={() => onSelect(event)}
      aria-pressed={selected}
      className={cn(
        'relative flex w-full flex-col gap-1 border-b border-[var(--separator)] px-3 py-2 text-left',
        'transition-colors duration-100',
        selected ? 'bg-accent/10' : 'hover:bg-[var(--fill-1)]',
        isClosed && 'opacity-55',
        isNew && 'animate-event-enter',
      )}
    >
      <span className={cn('absolute inset-y-0 left-0 w-0.5', styles.rail)} aria-hidden="true" />

      <div className="flex items-center gap-2">
        <SeverityBadge severity={event.severity} size="compact" />
        <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-fg">
          {meta.shortLabel}
        </span>
        <StatusBadge status={event.status} />
      </div>

      <div className="flex items-center gap-2 text-[11px]">
        <span className="flex min-w-0 items-center gap-1 font-mono text-fg-muted">
          <span className="truncate">{event.sourceIp}</span>
          <ArrowRight className="h-2.5 w-2.5 shrink-0 text-fg-dim" />
          <span className="truncate">
            {event.destinationIp}
            {event.destinationPort ? `:${event.destinationPort}` : ''}
          </span>
        </span>
        <span className="ml-auto shrink-0 text-fg-dim tabular">{relativeTime(event.timestamp, now)}</span>
      </div>

      <div className="truncate text-[11px] text-fg-dim">{event.description}</div>
    </button>
  );
});
