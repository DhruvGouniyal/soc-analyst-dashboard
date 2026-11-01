import { Crosshair, Globe, Radar } from 'lucide-react';
import { useMemo } from 'react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import {
  deriveIndicators,
  deriveMitreCoverage,
  type Indicator,
  type TechniqueCoverage,
} from '@/services/derived';
import { relativeTime } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Panel } from '@/components/ui/Panel';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { EmptyState, Skeleton } from '@/components/ui/States';

export function ThreatIntelPage() {
  const { events, loading } = useSecurityFeed();
  const now = useClock(2000);
  const indicators = useMemo(() => deriveIndicators(events, now), [events, now]);
  const coverage = useMemo(() => deriveMitreCoverage(events, now), [events, now]);

  return (
    <div className="h-full overflow-y-auto p-3">
      <div className="grid grid-cols-1 gap-2 xl:grid-cols-3">
        <Panel
          title="Indicators of Compromise"
          meta={loading ? undefined : `${indicators.length} observed`}
          flush
          className="xl:col-span-2"
        >
          {loading ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 6 }, (_, i) => (
                <Skeleton key={i} className="h-12" />
              ))}
            </div>
          ) : indicators.length === 0 ? (
            <EmptyState
              icon={<Crosshair className="h-5 w-5" />}
              title="No indicators observed"
              description="No external addresses have generated activity in the retained window."
            />
          ) : (
            <ul className="divide-y divide-line/60">
              {indicators.map((indicator) => (
                <IndicatorRow key={`${indicator.type}-${indicator.value}`} indicator={indicator} now={now} />
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="MITRE ATT&CK Coverage" meta="Observed techniques" flush className="xl:col-span-1">
          {loading ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 5 }, (_, i) => (
                <Skeleton key={i} className="h-12" />
              ))}
            </div>
          ) : coverage.length === 0 ? (
            <EmptyState icon={<Radar className="h-5 w-5" />} title="No techniques mapped" />
          ) : (
            <ul className="divide-y divide-line/60">
              {coverage.map((entry) => (
                <TechniqueRow key={entry.technique.id} entry={entry} now={now} />
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function IndicatorRow({ indicator, now }: { indicator: Indicator; now: number }) {
  const styles = SEVERITY_STYLES[indicator.severity];
  const isSource = indicator.type === 'ip-source';

  return (
    <li className="relative flex items-center gap-3 px-3 py-2.5 hover:bg-surface-hover">
      <span className={cn('absolute inset-y-0 left-0 w-0.5', styles.rail)} aria-hidden="true" />
      <span
        className={cn('flex h-7 w-7 shrink-0 items-center justify-center rounded border', styles.tint)}
        title={isSource ? 'Attacking source' : 'Outbound destination'}
      >
        {isSource ? <Crosshair className={cn('h-3.5 w-3.5', styles.text)} /> : <Globe className={cn('h-3.5 w-3.5', styles.text)} />}
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-[12px] font-medium text-fg">{indicator.value}</span>
          <span className="rounded border border-line px-1 text-[9px] text-fg-dim uppercase">
            {isSource ? 'source' : 'destination'}
          </span>
        </div>
        <div className="mt-0.5 truncate text-[10.5px] text-fg-dim">
          {EVENT_TYPES[indicator.dominantThreat].shortLabel}
          {indicator.technique ? ` · ${indicator.technique.id} ${indicator.technique.name}` : ''}
        </div>
      </div>

      <div className="hidden shrink-0 text-right sm:block">
        <div className="text-[10.5px] text-fg-dim">first {relativeTime(indicator.firstSeen, now)}</div>
        <div className="text-[10.5px] text-fg-dim">last {relativeTime(indicator.lastSeen, now)}</div>
      </div>

      <div className="shrink-0 text-right">
        <div className="flex items-center justify-end gap-1.5">
          <SeverityBadge severity={indicator.severity} size="compact" />
          <span
            className={cn('rounded border px-1.5 py-0.5 text-[10px] font-semibold tabular', styles.badge)}
            title={`Reputation risk ${indicator.riskScore} of 100`}
          >
            {indicator.riskScore}
          </span>
        </div>
        <div className="mt-1 text-[10px] text-fg-dim tabular">
          {indicator.eventCount} events · {indicator.confidence}% conf
        </div>
      </div>
    </li>
  );
}

function TechniqueRow({ entry, now }: { entry: TechniqueCoverage; now: number }) {
  const styles = SEVERITY_STYLES[entry.severity];
  return (
    <li className="px-3 py-2.5 hover:bg-surface-hover">
      <div className="flex items-center gap-2">
        <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', styles.dot)} aria-hidden="true" />
        <a
          href={entry.technique.url}
          target="_blank"
          rel="noreferrer noopener"
          className="text-[12px] font-medium text-accent hover:underline"
        >
          {entry.technique.id}
        </a>
        <span className="min-w-0 flex-1 truncate text-[11.5px] text-fg">{entry.technique.name}</span>
        <span className="shrink-0 text-[11px] text-fg-muted tabular">{entry.count}</span>
      </div>
      <div className="mt-0.5 flex items-center justify-between pl-3.5 text-[10px] text-fg-dim">
        <span>{entry.technique.tactic}</span>
        <span className="tabular">last {relativeTime(entry.lastSeen, now)}</span>
      </div>
    </li>
  );
}
