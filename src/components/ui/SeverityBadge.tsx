import { CircleAlert, Info, OctagonAlert, TriangleAlert } from 'lucide-react';
import type { ComponentType } from 'react';
import { SEVERITY_META } from '@/config/severity';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { Severity } from '@/types/security';

/**
 * Severity is never communicated by color alone — every badge carries an icon
 * and a text label, so the interface stays readable for color-vision
 * deficiencies and in grayscale screenshots.
 */
const SEVERITY_ICONS: Record<Severity, ComponentType<{ className?: string }>> = {
  critical: OctagonAlert,
  high: TriangleAlert,
  medium: CircleAlert,
  low: Info,
};

interface SeverityBadgeProps {
  severity: Severity;
  /** `compact` uses the abbreviated label for dense table cells. */
  size?: 'compact' | 'default';
  className?: string;
}

export function SeverityBadge({ severity, size = 'default', className }: SeverityBadgeProps) {
  const meta = SEVERITY_META[severity];
  const styles = SEVERITY_STYLES[severity];
  const Icon = SEVERITY_ICONS[severity];

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-semibold tracking-wide uppercase',
        size === 'compact' ? 'text-[10px]' : 'text-[10.5px]',
        styles.badge,
        className,
      )}
    >
      <Icon className="h-3 w-3 shrink-0" />
      {size === 'compact' ? meta.abbr : meta.label}
    </span>
  );
}

export { SEVERITY_ICONS };
