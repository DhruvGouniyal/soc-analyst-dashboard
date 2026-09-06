import { Activity, ArrowDown, ArrowRight, ArrowUp, Crosshair, OctagonAlert, TriangleAlert } from 'lucide-react';
import { motion, useReducedMotion } from 'motion/react';
import type { ComponentType, ReactNode } from 'react';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { SecurityKpis, Severity } from '@/types/security';
import { Skeleton } from '@/components/ui/States';
import CountUp from '@/components/reactbits/CountUp';
import SpotlightCard from '@/components/reactbits/SpotlightCard';
import { Tilt3D } from '@/components/ui/Tilt3D';

/**
 * Cursor glow. White everywhere except critical, which is the one card allowed
 * to spend the product's single hue.
 */
const SPOTLIGHT: Record<Severity | 'neutral', `rgba(${number}, ${number}, ${number}, ${number})`> = {
  critical: 'rgba(255, 69, 58, 0.16)',
  high: 'rgba(255, 255, 255, 0.11)',
  medium: 'rgba(255, 255, 255, 0.08)',
  low: 'rgba(255, 255, 255, 0.06)',
  neutral: 'rgba(255, 255, 255, 0.09)',
};

interface KpiCardProps {
  label: string;
  value: number;
  footnote: ReactNode;
  icon: ComponentType<{ className?: string }>;
  /** Severity tone, or `null` for a neutral informational card. */
  tone: Severity | null;
  delta?: ReactNode;
  /** Makes the card a filter control when provided. */
  onClick?: () => void;
  active?: boolean;
  /** Stagger position for the entrance. */
  index: number;
}

function KpiCard({ label, value, footnote, icon: Icon, tone, delta, onClick, active, index }: KpiCardProps) {
  const styles = tone ? SEVERITY_STYLES[tone] : null;
  const interactive = Boolean(onClick);
  const reduce = useReducedMotion();

  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{
        duration: 0.52,
        delay: index * 0.055,
        // iOS presentation curve: quick departure, long soft settle.
        ease: [0.32, 0.72, 0, 1],
      }}
      // Hover lift is 1.5%, not 5%. Apple never scales a resting surface far.
      whileTap={reduce || !interactive ? undefined : { scale: 0.985 }}
      className="stage-3d h-full"
    >
      <Tilt3D className="h-full" amplitude={9} scaleOnHover={1.02}>
      <SpotlightCard
        className={cn(
          'liquid ios-transition flex h-full flex-col gap-3 p-5',
          active && 'border-white/45 bg-[var(--fill-2)]',
          interactive && 'cursor-pointer hover:border-[var(--color-line-strong)]',
        )}
        spotlightColor={SPOTLIGHT[tone ?? 'neutral']}
      >
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
          className="tilt-layer flex h-full flex-col gap-3 outline-none"
        >
          {/* Icon chip carries the severity tone; the text label carries the
              meaning, so the card never depends on color alone. */}
          <span className="icon-chip shrink-0" aria-hidden="true">
            <Icon className={cn('h-4 w-4', styles ? styles.text : 'text-fg-muted')} />
          </span>

          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] leading-tight font-medium text-fg-muted">{label}</span>

            <div className="flex items-center gap-2.5">
              <CountUp
                to={value}
                className="text-[32px] leading-none font-semibold tracking-tight text-fg tabular"
              />
              {delta}
            </div>
          </div>

          <div className="mt-auto text-[11px] leading-tight text-fg-dim">{footnote}</div>
        </div>
      </SpotlightCard>
      </Tilt3D>
    </motion.div>
  );
}

/**
 * Signed change rendered as a pill. The arrow, not the color, is the primary
 * cue — the tint is reinforcement for sighted users at a glance.
 */
function DeltaPill({ value, suffix, invert }: { value: number; suffix: string; invert?: boolean }) {
  const rising = value > 0;
  const flat = value === 0;
  const Icon = flat ? ArrowRight : rising ? ArrowUp : ArrowDown;
  // For threat metrics, "up" is bad; `invert` flips that for metrics where
  // rising is neutral.
  const bad = !flat && rising !== Boolean(invert);
  const tone = flat
    ? 'text-fg-dim bg-[var(--fill-1)] border-[var(--separator)]'
    : bad
      ? 'text-crit bg-crit/12 border-crit/30'
      : 'text-fg bg-[var(--fill-2)] border-[var(--separator)]';

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold',
        tone,
      )}
    >
      <Icon className="h-3 w-3 shrink-0" />
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
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-[156px] rounded-[var(--radius-card)]" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        index={0}
        label="Critical Alerts"
        value={kpis.criticalCount}
        icon={OctagonAlert}
        tone="critical"
        active={activeSeverity === 'critical'}
        onClick={() => onSelectSeverity('critical')}
        delta={<DeltaPill value={kpis.criticalDeltaLastHour} suffix="" />}
        footnote="Open queue vs. previous hour"
      />
      <KpiCard
        index={1}
        label="High Severity"
        value={kpis.highCount}
        icon={TriangleAlert}
        tone="high"
        active={activeSeverity === 'high'}
        onClick={() => onSelectSeverity('high')}
        delta={<DeltaPill value={kpis.highDeltaPercent} suffix="%" />}
        footnote="Volume, hour over hour"
      />
      <KpiCard
        index={2}
        label="Security Events"
        value={kpis.totalEvents}
        icon={Activity}
        tone={null}
        footnote="Last 24 hours"
      />
      <KpiCard
        index={3}
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
