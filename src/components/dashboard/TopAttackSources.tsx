import { Ban, Crosshair } from 'lucide-react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { riskToSeverity } from '@/services/riskEngine';
import { relativeTime } from '@/services/time';
import type { AttackSource } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { EmptyState, Skeleton } from '@/components/ui/States';
import DecryptedText from '@/components/reactbits/DecryptedText';

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
    <Panel title="Top Attack Sources" meta="Last 24 hours · ranked by risk" className="min-h-[280px]">
      {loading ? (
        <div className="space-y-4 pt-2">
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-9" />
          ))}
        </div>
      ) : sources.length === 0 ? (
        <EmptyState
          icon={<Crosshair className="h-5 w-5" />}
          title="No attack sources observed"
          description="No external host has generated security events in the retained window."
        />
      ) : (
        <ul className="space-y-3.5 pt-1">
          {sources.map((source) => {
            const severity = riskToSeverity(source.riskScore);
            const styles = SEVERITY_STYLES[severity];
            const isActive = source.ip === activeIp;
            const fill = (source.eventCount / maxCount) * 100;

            return (
              <li key={source.ip} className="group">
                <div className="mb-1.5 flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onSelectSource(source.ip)}
                    aria-pressed={isActive}
                    title={`Filter events from ${source.ip}`}
                    className={cn(
                      'min-w-0 flex-1 truncate rounded-[var(--radius-control)] text-left font-mono text-[12.5px] font-medium transition-colors',
                      isActive ? 'text-accent' : 'text-fg hover:text-accent',
                    )}
                  >
                    {/* Scramble-decode on hover. The address is always present
                        in the DOM for screen readers; only the glyphs animate. */}
                    <DecryptedText
                      text={source.ip}
                      animateOn="hover"
                      sequential
                      revealDirection="start"
                      speed={38}
                      maxIterations={12}
                      characters="0123456789."
                      className="font-mono"
                      encryptedClassName="font-mono text-fg-dim"
                    />
                  </button>

                  <span
                    className={cn(
                      'shrink-0 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold tabular',
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
                    className="shrink-0 rounded-full p-1.5 text-fg-dim opacity-0 transition-opacity group-hover:opacity-100 hover:bg-crit/15 hover:text-crit focus-visible:opacity-100"
                  >
                    <Ban className="h-3.5 w-3.5" />
                  </button>
                </div>

                {/* Bar is proportional to the busiest source, with the count sitting
                    at the track's end so rows compare at a glance. */}
                <div className="flex items-center gap-2.5">
                  <div
                    className={cn(
                      'h-2 min-w-0 flex-1 overflow-hidden rounded-full transition-colors',
                      isActive ? 'bg-accent/20' : 'bg-line',
                    )}
                  >
                    <div
                      className={cn('h-full rounded-full transition-[width] duration-500', styles.bar)}
                      style={{ width: `${Math.max(2, fill)}%` }}
                    />
                  </div>
                  <span className="w-12 shrink-0 text-right text-[11.5px] font-medium text-fg-muted tabular">
                    {source.eventCount.toLocaleString('en-US')}
                  </span>
                </div>

                <div className="mt-1.5 flex items-center justify-between gap-2 text-[11px] text-fg-dim">
                  <span className="truncate">{EVENT_TYPES[source.dominantThreat].shortLabel}</span>
                  <span className="shrink-0 tabular">{relativeTime(source.lastSeen, now)}</span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
