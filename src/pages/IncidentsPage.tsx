import { Flame, ShieldCheck, ShieldX, Zap } from 'lucide-react';
import { useMemo } from 'react';
import { EVENT_TYPES } from '@/config/eventTypes';
import { SEVERITY_STYLES } from '@/config/theme';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { deriveIncidents, type Incident, type IncidentStatus } from '@/services/derived';
import { clockTime, relativeTime } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Panel } from '@/components/ui/Panel';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { EmptyState, Skeleton } from '@/components/ui/States';

const STATUS_META: Record<
  IncidentStatus,
  { label: string; className: string; icon: typeof Flame }
> = {
  active: { label: 'Active', className: 'text-crit border-crit/40 bg-crit/10', icon: Zap },
  contained: { label: 'Contained', className: 'text-low border-low/40 bg-low/10', icon: ShieldX },
  resolved: { label: 'Resolved', className: 'text-ok border-ok/40 bg-ok/10', icon: ShieldCheck },
};

export function IncidentsPage() {
  const { events, loading } = useSecurityFeed();
  const now = useClock(2000);
  const incidents = useMemo(() => deriveIncidents(events, now), [events, now]);

  const counts = useMemo(() => {
    const c = { active: 0, contained: 0, resolved: 0 };
    for (const incident of incidents) c[incident.status] += 1;
    return c;
  }, [incidents]);

  return (
    <div className="h-full overflow-y-auto p-3">
      <div className="mb-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <SummaryTile label="Total Incidents" value={incidents.length} tone="text-fg" />
        <SummaryTile label="Active" value={counts.active} tone="text-crit" />
        <SummaryTile label="Contained" value={counts.contained} tone="text-low" />
        <SummaryTile label="Resolved" value={counts.resolved} tone="text-ok" />
      </div>

      <Panel title="Correlated Incidents" meta="Last 24 hours · grouped by source" flush>
        {loading ? (
          <div className="space-y-2 p-3">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
        ) : incidents.length === 0 ? (
          <EmptyState
            icon={<Flame className="h-5 w-5" />}
            title="No active incidents"
            description="No source has produced a correlated high-severity chain in the retained window."
          />
        ) : (
          <ul className="divide-y divide-line/60">
            {incidents.map((incident) => (
              <IncidentRow key={incident.id} incident={incident} now={now} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function SummaryTile({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded border border-line bg-surface p-3">
      <div className="label-caps mb-1">{label}</div>
      <div className={cn('text-2xl leading-none font-semibold tabular', tone)}>{value}</div>
    </div>
  );
}

function IncidentRow({ incident, now }: { incident: Incident; now: number }) {
  const styles = SEVERITY_STYLES[incident.severity];
  const status = STATUS_META[incident.status];
  const StatusIcon = status.icon;
  const durationMin = Math.max(1, Math.round((incident.lastSeen - incident.firstSeen) / 60000));

  return (
    <li className={cn('relative px-3 py-3 transition-colors hover:bg-surface-hover', incident.status === 'resolved' && 'opacity-70')}>
      <span className={cn('absolute inset-y-0 left-0 w-0.5', styles.rail)} aria-hidden="true" />

      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={incident.severity} size="compact" />
        <span className="text-[13px] font-semibold text-fg">{incident.title}</span>
        <span className="font-mono text-[11px] text-fg-muted">{incident.sourceIp}</span>
        <span
          className={cn(
            'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium',
            status.className,
          )}
        >
          <StatusIcon className="h-2.5 w-2.5" />
          {status.label}
        </span>
        <span className="ml-auto shrink-0 text-[10.5px] text-fg-dim tabular">
          {incident.eventCount} events · {durationMin}m · updated {relativeTime(incident.lastSeen, now)}
        </span>
      </div>

      <p className="mb-2 text-[11.5px] leading-relaxed text-fg-muted">{incident.narrative}</p>

      <div className="flex flex-wrap items-center gap-1.5">
        {incident.stages.map((stage) => (
          <span
            key={stage}
            className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10px] text-fg-dim"
          >
            {EVENT_TYPES[stage].shortLabel}
          </span>
        ))}
        {incident.techniques.map((technique) => (
          <a
            key={technique.id}
            href={technique.url}
            target="_blank"
            rel="noreferrer noopener"
            title={`${technique.name} · ${technique.tactic}`}
            className="rounded border border-accent/30 bg-accent/5 px-1.5 py-0.5 text-[10px] font-medium text-accent hover:bg-accent/15"
          >
            {technique.id}
          </a>
        ))}
        <span className="ml-auto text-[10px] text-fg-dim tabular" title="First seen">
          since {clockTime(incident.firstSeen)}
        </span>
      </div>
    </li>
  );
}
