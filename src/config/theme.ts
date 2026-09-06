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

/**
 * Monochrome severity.
 *
 * Critical owns the only hue in the product (systemRed). Everything below it is
 * a descending greyscale intensity ramp — white, mid grey, dark grey — which is
 * why every badge also carries an icon and a written label: the ramp gives you
 * the at-a-glance ordering, the glyph and word give you the certainty.
 *
 * Chart hexes are lifted relative to the UI values because a thin 1.75px stroke
 * on pure black needs more luminance than a filled badge does to read.
 */
export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    badge: 'bg-crit/15 text-crit border-crit/45',
    rail: 'bg-crit',
    dot: 'bg-crit',
    text: 'text-crit',
    tint: 'bg-crit/10 border-crit/30',
    bar: 'bg-crit',
    hex: '#ff453a',
  },
  high: {
    badge: 'bg-white/14 text-white border-white/35',
    rail: 'bg-white',
    dot: 'bg-white',
    text: 'text-white',
    tint: 'bg-white/8 border-white/20',
    bar: 'bg-white',
    hex: '#ffffff',
  },
  medium: {
    badge: 'bg-white/8 text-[#c7c7cc] border-white/20',
    rail: 'bg-[#8e8e93]',
    dot: 'bg-[#8e8e93]',
    text: 'text-[#c7c7cc]',
    tint: 'bg-white/5 border-white/12',
    bar: 'bg-[#8e8e93]',
    hex: '#8e8e93',
  },
  low: {
    badge: 'bg-white/5 text-[#8e8e93] border-white/12',
    rail: 'bg-[#48484a]',
    dot: 'bg-[#48484a]',
    text: 'text-[#8e8e93]',
    tint: 'bg-white/4 border-white/8',
    bar: 'bg-[#5a5a5e]',
    hex: '#6e6e73',
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
