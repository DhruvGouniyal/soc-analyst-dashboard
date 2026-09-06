import { EVENT_STATUS_META } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { EventStatus } from '@/types/security';

/** Lifecycle chip shown on feed rows and in the detail panel. */
export function StatusBadge({ status, className }: { status: EventStatus; className?: string }) {
  const meta = EVENT_STATUS_META[status];
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10.5px] font-medium',
        meta.className,
        className,
      )}
    >
      {meta.label}
    </span>
  );
}

interface StatusDotProps {
  /** Tailwind background class, e.g. `bg-ok`. */
  tone: string;
  /** Slow pulse, reserved for genuinely live indicators. */
  pulse?: boolean;
  className?: string;
}

export function StatusDot({ tone, pulse, className }: StatusDotProps) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'inline-block h-1.5 w-1.5 shrink-0 rounded-full',
        tone,
        pulse && 'animate-pulse-dot',
        className,
      )}
    />
  );
}

interface MeterProps {
  value: number;
  tone: string;
  className?: string;
}

/** Thin utilization bar used for CPU/memory and source volume. */
export function Meter({ value, tone, className }: MeterProps) {
  return (
    <div className={cn('h-1 w-full overflow-hidden rounded-full bg-line', className)}>
      <div
        className={cn('h-full rounded-full transition-[width] duration-300', tone)}
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}
