import { Activity, ArrowDown, ArrowRight, ArrowUp, Crosshair, OctagonAlert, TriangleAlert } from 'lucide-react';
import type { ComponentType, ReactNode } from 'react';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { formatCount } from '@/services/time';
import type { SecurityKpis, Severity } from '@/types/security';
import { Skeleton } from '@/components/ui/States';

interface KpiCardProps {
  label: string;
  value: number;
  /** Formatted footnote, e.g. "3 requiring attention". */
  footnote: ReactNode;
  icon: ComponentType<{ className?: string }>;
  /** Severity tone, or `null` for a neutral informational card. */
  tone: Severity | null;
  /** Makes the card a filter control when provided. */
  onClick?: () => void;
  active?: boolean;
}

function KpiCard({ label, value, footnote, icon: Icon, tone, onClick, active }: KpiCardProps) {
  const styles = tone ? SEVERITY_STYLES[tone] : null;
  const interactive = Boolean(onClick);

  return (
    <div
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (!interactive) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick?.();
        }
      }}
      aria-pressed={interactive ? active : undefined}
      className={cn(
        'relative flex flex-col justify-between overflow-hidden rounded border bg-surface p-3',
        'transition-colors duration-100',
        active ? 'border-accent/60 bg-surface-raised' : 'border-line',
        interactive && 'cursor-pointer hover:border-line-strong hover:bg-surface-raised',
      )}
    >
      {/* Severity rail — the non-color cue is the icon and label below. */}
      <span
        className={cn('absolute inset-y-0 left-0 w-0.5', styles ? styles.rail : 'bg-line-strong')}
        aria-hidden="true"
      />

      <div className="mb-2 flex items-start justify-between gap-2">
        <span className="label-caps leading-tight">{label}</span>
        <Icon className={cn('h-3.5 w-3.5 shrink-0', styles ? styles.text : 'text-fg-dim')} />
      </div>

      <div className="flex items-baseline gap-2">
        <span className="text-2xl leading-none font-semibold text-fg tabular">
          {formatCount(value)}
        </span>
      </div>

      <div className="mt-1.5 text-[10.5px] text-fg-dim">{footnote}</div>
    </div>
  );
}

/** Renders a signed change with a direction arrow, never color alone. */
function Delta({ value, suffix, invert }: { value: number; suffix: string; invert?: boolean }) {
  const rising = value > 0;
  const flat = value === 0;
  const Icon = flat ? ArrowRight : rising ? ArrowUp : ArrowDown;
  // For threat metrics, "up" is bad; `invert` flips that for metrics where
  // rising is neutral.
  const tone = flat
    ? 'text-fg-dim'
    : rising !== Boolean(invert)
      ? 'text-crit'
      : 'text-ok';

  return (
    <span className={cn('inline-flex items-center gap-0.5', tone)}>
      <Icon className="h-2.5 w-2.5" />
      <span className="tabular">
        {Math.abs(value)}
        {suffix}
      </span>
    </span>
  );
}

interface KpiRowProps {
  kpis: SecurityKpis;
  loading: boolean;
  /** Severity currently pinned by a card click, if any. */
  activeSeverity: Severity | null;
  onSelectSeverity: (severity: Severity) => void;
}

export function KpiRow({ kpis, loading, activeSeverity, onSelectSeverity }: KpiRowProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-[92px]" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-2 xl:grid-cols-4">
      <KpiCard
        label="Critical Alerts"
        value={kpis.criticalCount}
        icon={OctagonAlert}
        tone="critical"
        active={activeSeverity === 'critical'}
        onClick={() => onSelectSeverity('critical')}
        footnote={
          <>
            <Delta value={kpis.criticalDeltaLastHour} suffix="" /> from last hour
          </>
        }
      />
      <KpiCard
        label="High Severity"
        value={kpis.highCount}
        icon={TriangleAlert}
        tone="high"
        active={activeSeverity === 'high'}
        onClick={() => onSelectSeverity('high')}
        footnote={
          <>
            <Delta value={kpis.highDeltaPercent} suffix="%" /> hour over hour
          </>
        }
      />
      <KpiCard
        label="Security Events"
        value={kpis.totalEvents}
        icon={Activity}
        tone={null}
        footnote="Last 24 hours"
      />
      <KpiCard
        label="Active Threats"
        value={kpis.activeThreats}
        icon={Crosshair}
        tone="medium"
        footnote={
          kpis.threatsRequiringAttention > 0
            ? `${kpis.threatsRequiringAttention} requiring attention`
            : 'All acknowledged'
        }
      />
    </div>
  );
}
