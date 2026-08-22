/**
 * The single source of truth for severity semantics.
 *
 * Domain-only on purpose: no colors or CSS live here so the same weights can
 * be reused by a backend detection engine later. Presentation lives in
 * `config/theme.ts`.
 */
import type { Severity } from '@/types/security';

/** Most severe first. Drives sort order and display order everywhere. */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low'] as const;

export interface SeverityMeta {
  key: Severity;
  label: string;
  /** Compact form for dense table cells. */
  abbr: string;
  /**
   * Risk contribution of a single event at this severity. Consumed only by
   * `services/riskEngine.ts` — tune scoring there, not in components.
   */
  weight: number;
  /** Lower rank = more severe. */
  rank: number;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: { key: 'critical', label: 'Critical', abbr: 'CRIT', weight: 25, rank: 0 },
  high: { key: 'high', label: 'High', abbr: 'HIGH', weight: 10, rank: 1 },
  medium: { key: 'medium', label: 'Medium', abbr: 'MED', weight: 4, rank: 2 },
  low: { key: 'low', label: 'Low', abbr: 'LOW', weight: 1, rank: 3 },
};

/** Sort comparator: most severe first, newest first within a severity. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_META[a].rank - SEVERITY_META[b].rank;
}

export function isSeverityAtLeast(value: Severity, floor: Severity): boolean {
  return SEVERITY_META[value].rank <= SEVERITY_META[floor].rank;
}
