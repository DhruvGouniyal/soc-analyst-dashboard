import { ScrollText, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { clockTime } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import type { LogSource, SecurityEvent } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { EmptyState, SkeletonRows } from '@/components/ui/States';

/** Rendered at once — the store holds far more; this is a tail view. */
const RENDER_LIMIT = 300;

const SOURCES: (LogSource | 'all')[] = ['all', 'auth.log', 'syslog', 'audit.log', 'suricata', 'netflow'];

/**
 * Raw collector output. Every event carries the verbatim log line the detection
 * fired on, so this is a real log tail — the same lines an analyst would grep on
 * the host — filtered by source and free-text search rather than a fabricated
 * feed.
 */
export function LogsPage() {
  const { events, loading } = useSecurityFeed();
  const now = useClock(2000);
  const [query, setQuery] = useState('');
  const [source, setSource] = useState<LogSource | 'all'>('all');

  const lines = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events
      .filter((event) => event.rawLog)
      .filter((event) => source === 'all' || event.logSource === source)
      .filter((event) => !needle || event.rawLog!.toLowerCase().includes(needle))
      .slice(0, RENDER_LIMIT);
  }, [events, query, source]);

  return (
    <div className="h-full p-3">
      <Panel
        title="Log Stream"
        meta={loading ? undefined : `${lines.length} lines${query || source !== 'all' ? ' (filtered)' : ''}`}
        flush
        className="h-full"
      >
        <div className="flex h-full min-h-0 flex-col">
          <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-3 py-2">
            <label className="relative min-w-48 flex-1">
              <Search className="pointer-events-none absolute top-1/2 left-2 h-3 w-3 -translate-y-1/2 text-fg-dim" />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search raw log lines…"
                aria-label="Search log lines"
                className="h-6 w-full rounded border border-line bg-canvas pr-2 pl-7 text-[11px] text-fg placeholder:text-fg-dim focus:border-accent/60 focus:outline-none"
              />
            </label>
            <div className="flex items-center gap-1">
              {SOURCES.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSource(s)}
                  aria-pressed={source === s}
                  className={cn(
                    'rounded border px-1.5 py-0.5 font-mono text-[10.5px]',
                    source === s
                      ? 'border-accent/50 bg-accent/15 text-accent'
                      : 'border-line bg-canvas text-fg-dim hover:border-line-strong hover:text-fg-muted',
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-auto">
            {loading ? (
              <SkeletonRows rows={8} />
            ) : lines.length === 0 ? (
              <EmptyState
                icon={<ScrollText className="h-5 w-5" />}
                title="No log lines match"
                description="Widen the source filter or clear the search query."
              />
            ) : (
              <ul className="divide-y divide-line/50 font-mono">
                {lines.map((event) => (
                  <LogLine key={event.id} event={event} now={now} />
                ))}
              </ul>
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function LogLine({ event, now: _now }: { event: SecurityEvent; now: number }) {
  const styles = SEVERITY_STYLES[event.severity];
  return (
    <li className="flex items-start gap-2 px-3 py-1.5 text-[11px] leading-relaxed hover:bg-surface-hover">
      <span className="shrink-0 text-fg-dim tabular">{clockTime(event.timestamp)}</span>
      <span className={cn('mt-1 h-1.5 w-1.5 shrink-0 rounded-full', styles.dot)} aria-hidden="true" />
      <span className="w-16 shrink-0 truncate text-fg-dim" title={event.logSource}>
        {event.logSource}
      </span>
      <span className="min-w-0 flex-1 break-all whitespace-pre-wrap text-fg-muted">
        {event.rawLog}
      </span>
      <span className="hidden shrink-0 text-fg-dim md:inline">{EVENT_TYPES[event.eventType].shortLabel}</span>
    </li>
  );
}
