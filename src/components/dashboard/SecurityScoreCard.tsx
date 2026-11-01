import { SEVERITY_META, SEVERITY_ORDER } from '@/config/severity';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { SecurityScore } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { Skeleton } from '@/components/ui/States';

/** Arc geometry — a 240° sweep reads as a gauge without a full ring's bulk. */
const RADIUS = 42;
const SWEEP_DEGREES = 240;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const ARC_LENGTH = (SWEEP_DEGREES / 360) * CIRCUMFERENCE;

const BAND_TONE: Record<SecurityScore['band'], { text: string; stroke: string }> = {
  good: { text: 'text-ok', stroke: '#3fa45b' },
  moderate: { text: 'text-med', stroke: '#e0a11a' },
  elevated: { text: 'text-high', stroke: '#ef7014' },
  critical: { text: 'text-crit', stroke: '#e5484d' },
};

interface SecurityScoreCardProps {
  score: SecurityScore;
  loading: boolean;
}

export function SecurityScoreCard({ score, loading }: SecurityScoreCardProps) {
  if (loading) {
    return (
      <Panel title="Security Score" className="min-h-[220px]">
        <Skeleton className="h-full min-h-[160px] w-full" />
      </Panel>
    );
  }

  const tone = BAND_TONE[score.band];
  const filled = (score.score / 100) * ARC_LENGTH;

  return (
    <Panel title="Security Score" meta="Open events · last 4 hours" className="min-h-[220px]">
      <div className="flex h-full flex-col items-center justify-between gap-3">
        <div className="relative flex items-center justify-center">
          <svg width="128" height="104" viewBox="0 0 128 104" role="img" aria-label={`Security score ${score.score} of 100, ${score.label}`}>
            {/* Rotated so the 240° arc opens downward, leaving room for the label. */}
            <g transform="rotate(150 64 52)">
              <circle
                cx="64"
                cy="52"
                r={RADIUS}
                fill="none"
                stroke="var(--color-line)"
                strokeWidth="7"
                strokeLinecap="round"
                strokeDasharray={`${ARC_LENGTH} ${CIRCUMFERENCE}`}
              />
              <circle
                cx="64"
                cy="52"
                r={RADIUS}
                fill="none"
                stroke={tone.stroke}
                strokeWidth="7"
                strokeLinecap="round"
                strokeDasharray={`${filled} ${CIRCUMFERENCE}`}
                className="transition-[stroke-dasharray] duration-500"
              />
            </g>
          </svg>

          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-1">
            <div className="flex items-baseline gap-0.5">
              <span className="text-3xl leading-none font-semibold text-fg tabular">{score.score}</span>
              <span className="text-xs text-fg-dim">/100</span>
            </div>
            <span className={cn('mt-1 text-[11px] font-medium', tone.text)}>{score.label}</span>
          </div>
        </div>

        {/* Contribution breakdown keeps the number accountable rather than opaque. */}
        <div className="w-full">
          <div className="label-caps mb-1.5">Contributing Events</div>
          {score.breakdown.length === 0 ? (
            <p className="text-[10.5px] text-fg-dim">
              No unresolved events in the scoring window.
            </p>
          ) : (
            <ul className="space-y-1">
              {SEVERITY_ORDER.map((severity) => {
                const entry = score.breakdown.find((item) => item.severity === severity);
                if (!entry) return null;
                return (
                  <li key={severity} className="flex items-center gap-2 text-[10.5px]">
                    <span
                      className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_STYLES[severity].dot)}
                      aria-hidden="true"
                    />
                    <span className="flex-1 text-fg-muted">{SEVERITY_META[severity].label}</span>
                    <span className="text-fg-dim tabular">{entry.count}</span>
                    <span className="w-10 text-right text-fg-dim tabular">−{entry.penalty}</span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  );
}
