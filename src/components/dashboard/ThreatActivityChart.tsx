import { useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { SEVERITY_META, SEVERITY_ORDER } from '@/config/severity';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { bucketActivity, TIME_RANGES, TIME_RANGE_KEYS } from '@/services/metrics';
import type { ActivityBucket, SecurityEvent, Severity, TimeRangeKey } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { ToggleGroup } from '@/components/ui/Button';
import { Skeleton } from '@/components/ui/States';

/** Short labels for the range switcher; full names live in TIME_RANGES. */
const RANGE_LABELS: Record<TimeRangeKey, string> = {
  '1h': '1H',
  '6h': '6H',
  '24h': '24H',
  '7d': '7D',
};

interface TooltipItem {
  dataKey?: string | number;
  value?: number;
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipItem[];
  label?: string | number;
}) {
  if (!active || !payload?.length) return null;

  // Recharts stacks bottom-up; reverse so the tooltip reads most-severe first.
  const rows = [...payload].reverse().filter((item) => (item.value ?? 0) > 0);
  const total = payload.reduce((sum, item) => sum + (item.value ?? 0), 0);

  return (
    <div className="rounded-[var(--radius-control)] border border-[var(--separator)] bg-[#2c2c2e] px-3 py-2.5 shadow-xl">
      <div className="mb-1.5 text-[10.5px] font-medium text-fg tabular">{label}</div>
      {rows.length === 0 ? (
        <div className="text-[10.5px] text-fg-dim">No events</div>
      ) : (
        <ul className="space-y-0.5">
          {rows.map((item) => {
            const severity = item.dataKey as Severity;
            return (
              <li key={severity} className="flex items-center gap-2 text-[10.5px]">
                <span
                  className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_STYLES[severity].dot)}
                  aria-hidden="true"
                />
                <span className="flex-1 text-fg-muted">{SEVERITY_META[severity].label}</span>
                <span className="font-medium text-fg tabular">{item.value}</span>
              </li>
            );
          })}
        </ul>
      )}
      <div className="mt-1.5 flex items-center justify-between gap-3 border-t border-[var(--separator)] pt-1.5 text-[10.5px]">
        <span className="text-fg-dim">Total</span>
        <span className="font-semibold text-fg tabular">{total}</span>
      </div>
    </div>
  );
}

interface ThreatActivityChartProps {
  events: SecurityEvent[];
  loading: boolean;
  /** Ticking clock so buckets roll forward as time passes. */
  now: number;
}

export function ThreatActivityChart({ events, loading, now }: ThreatActivityChartProps) {
  const [range, setRange] = useState<TimeRangeKey>('24h');
  const [hidden, setHidden] = useState<Severity[]>([]);

  const buckets: ActivityBucket[] = useMemo(
    () => bucketActivity(events, range, now),
    [events, range, now],
  );

  const totals = useMemo(() => {
    const sum: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const bucket of buckets) {
      for (const severity of SEVERITY_ORDER) sum[severity] += bucket[severity];
    }
    return sum;
  }, [buckets]);

  const windowTotal = SEVERITY_ORDER.reduce((sum, severity) => sum + totals[severity], 0);

  function toggleSeries(severity: Severity) {
    setHidden((current) =>
      current.includes(severity)
        ? current.filter((s) => s !== severity)
        : [...current, severity],
    );
  }

  // Show roughly eight x-axis labels regardless of bucket count.
  const tickInterval = Math.max(0, Math.floor(buckets.length / 8) - 1);

  return (
    <Panel
      title="Threat Activity"
      meta={`${windowTotal.toLocaleString('en-US')} events · ${TIME_RANGES[range].label.toLowerCase()}`}
      actions={
        <ToggleGroup<TimeRangeKey>
          label="Chart time range"
          value={range}
          onChange={setRange}
          options={TIME_RANGE_KEYS.map((key) => ({ value: key, label: RANGE_LABELS[key] }))}
        />
      }
      className="min-h-[340px]"
    >
      {loading ? (
        <Skeleton className="h-[240px] w-full" />
      ) : (
        <div className="flex h-full flex-col">
          {/* Legend doubles as a series filter. */}
          <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
            {SEVERITY_ORDER.map((severity) => {
              const isHidden = hidden.includes(severity);
              return (
                <button
                  key={severity}
                  type="button"
                  onClick={() => toggleSeries(severity)}
                  aria-pressed={!isHidden}
                  className={cn(
                    'flex items-center gap-1.5 rounded-full px-2 py-1 text-[11px] transition-opacity',
                    isHidden ? 'opacity-35' : 'opacity-100',
                    'hover:bg-[var(--fill-1)]',
                  )}
                  title={isHidden ? `Show ${SEVERITY_META[severity].label}` : `Hide ${SEVERITY_META[severity].label}`}
                >
                  <span
                    className={cn('h-2 w-2.5 rounded-full', SEVERITY_STYLES[severity].bar)}
                    aria-hidden="true"
                  />
                  <span className="text-fg-muted">{SEVERITY_META[severity].label}</span>
                  <span className="font-medium text-fg-dim tabular">{totals[severity]}</span>
                </button>
              );
            })}
          </div>

          {/*
            ResponsiveContainer measures its parent, and a percentage height
            cannot resolve against a flex child sized only by `min-height`.
            Anchoring it to an absolutely-positioned box gives it a definite
            containing block while keeping the width fluid.
          */}
          <div className="relative min-h-[250px] flex-1">
            <div className="absolute inset-0">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={buckets} margin={{ top: 4, right: 4, bottom: 0, left: -8 }}>
                  {/* Each series fades to nothing at the baseline so overlapping
                      bands stay readable where the stack is deep. */}
                  <defs>
                    {SEVERITY_ORDER.map((severity) => (
                      <linearGradient
                        key={severity}
                        id={`activity-fill-${severity}`}
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor={SEVERITY_STYLES[severity].hex}
                          stopOpacity={0.38}
                        />
                        <stop
                          offset="100%"
                          stopColor={SEVERITY_STYLES[severity].hex}
                          stopOpacity={0.04}
                        />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid stroke="#26262e" strokeDasharray="2 4" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: '#6b6b78', fontSize: 10.5 }}
                    tickLine={false}
                    axisLine={{ stroke: '#26262e' }}
                    interval={tickInterval}
                    minTickGap={8}
                  />
                  <YAxis
                    tick={{ fill: '#6b6b78', fontSize: 10.5 }}
                    tickLine={false}
                    axisLine={false}
                    width={44}
                    allowDecimals={false}
                  />
                  <Tooltip
                    content={<ChartTooltip />}
                    cursor={{ stroke: '#34343f', strokeWidth: 1 }}
                  />
                  {/* Stacked least-severe first so critical sits on top. */}
                  {[...SEVERITY_ORDER]
                    .reverse()
                    .filter((severity) => !hidden.includes(severity))
                    .map((severity) => (
                      <Area
                        key={severity}
                        type="monotone"
                        dataKey={severity}
                        stackId="severity"
                        stroke={SEVERITY_STYLES[severity].hex}
                        strokeWidth={1.75}
                        fill={`url(#activity-fill-${severity})`}
                        isAnimationActive={false}
                        dot={false}
                        activeDot={{ r: 2.5, strokeWidth: 0 }}
                      />
                    ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}
