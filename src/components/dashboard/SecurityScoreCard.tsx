import { SEVERITY_META, SEVERITY_ORDER } from '@/config/severity';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { SecurityScore } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { Skeleton } from '@/components/ui/States';

/** Full-ring geometry. A closed donut reads as a share of 100, not a dial. */
const RADIUS = 46;
const STROKE = 11;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * The ring is a greyscale intensity ramp that dims as posture degrades, and
 * turns red only in the band that actually demands action.
 */
const BAND_TONE: Record<SecurityScore['band'], { text: string; stroke: string }> = {
  good: { text: 'text-white', stroke: '#ffffff' },
  moderate: { text: 'text-[#c7c7cc]', stroke: '#c7c7cc' },
  elevated: { text: 'text-[#8e8e93]', stroke: '#8e8e93' },
  critical: { text: 'text-crit', stroke: '#ff453a' },
};

interface SecurityScoreCardProps {
  score: SecurityScore;
  loading: boolean;
}

export function SecurityScoreCard({ score, loading }: SecurityScoreCardProps) {
  if (loading) {
    return (
      <Panel title="Security Score" className="min-h-[280px]">
        <Skeleton className="h-full min-h-[200px] w-full" />
      </Panel>
    );
  }

  const tone = BAND_TONE[score.band];
  const filled = (score.score / 100) * CIRCUMFERENCE;

  return (
    <Panel title="Security Score" meta="Open events · last 4 hours" className="min-h-[280px]">
      <div className="flex h-full flex-col items-center gap-5 sm:flex-row sm:items-center sm:gap-6 xl:flex-col xl:items-center xl:gap-5">
        <div className="relative flex shrink-0 items-center justify-center">
          <svg
            width="132"
            height="132"
            viewBox="0 0 120 120"
            role="img"
            aria-label={`Security score ${score.score} of 100, ${score.label}`}
          >
            {/* -90° so the ring fills clockwise from twelve o'clock. */}
            <g transform="rotate(-90 60 60)">
              <circle
                cx="60"
                cy="60"
                r={RADIUS}
                fill="none"
                stroke="var(--color-line)"
                strokeWidth={STROKE}
              />
              <circle
                cx="60"
                cy="60"
                r={RADIUS}
                fill="none"
                stroke={tone.stroke}
                strokeWidth={STROKE}
                strokeLinecap="round"
                strokeDasharray={`${filled} ${CIRCUMFERENCE}`}
                className="transition-[stroke-dasharray] duration-500"
              />
            </g>
          </svg>

          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <div className="flex items-baseline gap-0.5">
              <span className="text-[34px] leading-none font-semibold tracking-tight text-fg tabular">
                {score.score}
              </span>
              <span className="text-[13px] text-fg-dim">/100</span>
            </div>
            <span className={cn('mt-1.5 text-[11.5px] font-semibold', tone.text)}>{score.label}</span>
          </div>
        </div>

        {/* Contribution breakdown keeps the number accountable rather than opaque. */}
        <div className="w-full min-w-0">
          <div className="label-caps mb-2.5">Contributing Events</div>
          {score.breakdown.length === 0 ? (
            <p className="text-[11.5px] text-fg-dim">No unresolved events in the scoring window.</p>
          ) : (
            <ul className="space-y-2">
              {SEVERITY_ORDER.map((severity) => {
                const entry = score.breakdown.find((item) => item.severity === severity);
                if (!entry) return null;
                return (
                  <li key={severity} className="flex items-center gap-2.5 text-[11.5px]">
                    <span
                      className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_STYLES[severity].dot)}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1 truncate text-fg-muted">
                      {SEVERITY_META[severity].label}
                    </span>
                    <span className="shrink-0 font-medium text-fg tabular">{entry.count}</span>
                    <span className="w-10 shrink-0 text-right text-fg-dim tabular">
                      -{entry.penalty}
                    </span>
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
