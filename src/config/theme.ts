/**
 * Presentation tokens for the severity and status systems.
 *
 * Kept separate from `config/severity.ts` so domain weights stay portable to a
 * backend while every visual treatment still resolves from one place.
 */
import type { EventStatus, HostStatus, NetworkState, Severity } from '@/types/security';

interface SeverityStyle {
  /** Filled badge, used in the feed and detail header. */
  badge: string;
  /** Left status rail on feed rows and cards. */
  rail: string;
  /** Solid indicator dot. */
  dot: string;
  /** Foreground-only treatment for inline text. */
  text: string;
  /** Tinted surface for KPI cards and detail blocks. */
  tint: string;
  /** Progress/volume bar fill. */
  bar: string;
  /** Chart series color — literal hex, since SVG fills can't read Tailwind classes. */
  hex: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    badge: 'bg-crit/15 text-crit border-crit/40',
    rail: 'bg-crit',
    dot: 'bg-crit',
    text: 'text-crit',
    tint: 'bg-crit/8 border-crit/25',
    bar: 'bg-crit',
    hex: '#e5484d',
  },
  high: {
    badge: 'bg-high/15 text-high border-high/40',
    rail: 'bg-high',
    dot: 'bg-high',
    text: 'text-high',
    tint: 'bg-high/8 border-high/25',
    bar: 'bg-high',
    hex: '#ef7014',
  },
  medium: {
    badge: 'bg-med/15 text-med border-med/40',
    rail: 'bg-med',
    dot: 'bg-med',
    text: 'text-med',
    tint: 'bg-med/8 border-med/25',
    bar: 'bg-med',
    hex: '#e0a11a',
  },
  low: {
    badge: 'bg-low/15 text-low border-low/40',
    rail: 'bg-low',
    dot: 'bg-low',
    text: 'text-low',
    tint: 'bg-low/8 border-low/25',
    bar: 'bg-low',
    hex: '#3b9eff',
  },
};

export const EVENT_STATUS_META: Record<EventStatus, { label: string; className: string }> = {
  new: { label: 'New', className: 'text-fg-muted border-line-strong bg-surface-raised' },
  investigating: { label: 'Investigating', className: 'text-med border-med/40 bg-med/10' },
  blocked: { label: 'Blocked', className: 'text-low border-low/40 bg-low/10' },
  resolved: { label: 'Resolved', className: 'text-ok border-ok/40 bg-ok/10' },
};

export const HOST_STATUS_META: Record<HostStatus, { label: string; dot: string; text: string }> = {
  online: { label: 'Online', dot: 'bg-ok', text: 'text-ok' },
  degraded: { label: 'Degraded', dot: 'bg-med', text: 'text-med' },
  offline: { label: 'Offline', dot: 'bg-fg-dim', text: 'text-fg-dim' },
};

export const NETWORK_STATE_META: Record<NetworkState, { label: string; text: string }> = {
  normal: { label: 'Normal', text: 'text-fg-muted' },
  elevated: { label: 'Elevated', text: 'text-med' },
  saturated: { label: 'Saturated', text: 'text-crit' },
};

/** Utilization thresholds shared by CPU/memory meters. */
export function utilizationTone(percent: number): string {
  if (percent >= 85) return 'bg-crit';
  if (percent >= 65) return 'bg-med';
  return 'bg-ok';
}
