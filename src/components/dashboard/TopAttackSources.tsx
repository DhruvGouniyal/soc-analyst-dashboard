import { Ban, Crosshair } from 'lucide-react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { riskToSeverity } from '@/services/riskEngine';
import { relativeTime } from '@/services/time';
import type { AttackSource } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { EmptyState, Skeleton } from '@/components/ui/States';
import { Meter } from '@/components/ui/StatusBadge';

interface TopAttackSourcesProps {
  sources: AttackSource[];
  loading: boolean;
  now: number;
  /** Filters the event feed to this IP. */
  onSelectSource: (ip: string) => void;
  /** IP currently pinned in the feed filter, if any. */
  activeIp: string | null;
  onBlock: (ip: string) => void;
}

export function TopAttackSources({
  sources,
  loading,
  now,
  onSelectSource,
  activeIp,
  onBlock,
}: TopAttackSourcesProps) {
  const maxCount = Math.max(1, ...sources.map((source) => source.eventCount));

  return (
    <Panel title="Top Attack Sources" meta="Last 24 hours · ranked by risk" flush className="min-h-[220px]">
      {loading ? (
        <div className="space-y-3 p-3">
          {Array.from({ length: 4 }, (_, i) => (
            <Skeleton key={i} className="h-11" />
          ))}
        </div>
      ) : sources.length === 0 ? (
        <EmptyState
          icon={<Crosshair className="h-5 w-5" />}
          title="No attack sources observed"
          description="No external host has generated security events in the retained window."
        />
      ) : (
        <ul>
          {sources.map((source) => {
            const severity = riskToSeverity(source.riskScore);
            const styles = SEVERITY_STYLES[severity];
            const isActive = source.ip === activeIp;

            return (
              <li key={source.ip} className="border-b border-line/60 last:border-b-0">
                <div
                  className={cn(
                    'group relative flex flex-col gap-1.5 px-3 py-2 transition-colors duration-100',
                    isActive ? 'bg-accent/10' : 'hover:bg-surface-hover',
                  )}
                >
                  <span
                    className={cn('absolute inset-y-0 left-0 w-0.5', styles.rail)}
                    aria-hidden="true"
                  />

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onSelectSource(source.ip)}
                      aria-pressed={isActive}
                      title={`Filter events from ${source.ip}`}
                      className="min-w-0 flex-1 text-left font-mono text-[12px] font-medium text-fg hover:text-accent"
                    >
                      {source.ip}
                    </button>

                    <span className="shrink-0 text-[11px] text-fg-muted tabular">
                      {source.eventCount.toLocaleString('en-US')} events
                    </span>

                    <span
                      className={cn(
                        'shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold tabular',
                        styles.badge,
                      )}
                      title={`Risk score ${source.riskScore} of 100`}
                    >
                      {source.riskScore}
                    </span>

                    <button
                      type="button"
                      onClick={() => onBlock(source.ip)}
                      title={`Block ${source.ip}`}
                      aria-label={`Block ${source.ip}`}
                      className="shrink-0 rounded p-1 text-fg-dim opacity-0 transition-opacity group-hover:opacity-100 hover:bg-crit/15 hover:text-crit focus-visible:opacity-100"
                    >
                      <Ban className="h-3 w-3" />
                    </button>
                  </div>

                  {/* Volume bar is proportional to the busiest source, so the
                      comparison between rows is meaningful. */}
                  <Meter
                    value={(source.eventCount / maxCount) * 100}
                    tone={styles.bar}
                    className="h-1"
                  />

                  <div className="flex items-center justify-between gap-2 text-[10.5px] text-fg-dim">
                    <span className="truncate">{EVENT_TYPES[source.dominantThreat].shortLabel}</span>
                    <span className="shrink-0 tabular">{relativeTime(source.lastSeen, now)}</span>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
