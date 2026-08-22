/**
 * Risk and scoring.
 *
 * Isolated on purpose: this is the layer most likely to be replaced by a real
 * algorithm (or by scores computed server-side) once the detection engine is
 * doing proper correlation. Nothing here touches React, and every tunable is a
 * named constant at the top rather than a magic number in a formula.
 */
import { SEVERITY_META } from '@/config/severity';
import type { SecurityEvent, SecurityScore, Severity } from '@/types/security';

/** Only events inside this window influence the current posture. */
const SCORE_WINDOW_MS = 4 * 60 * 60 * 1000;

/**
 * Controls how fast the score falls as pressure accumulates. Larger = more
 * forgiving. Tuned so an ordinary hour of mixed traffic sits in the 60s–70s,
 * leaving headroom for a real incident to move the number visibly.
 */
const SATURATION = 2200;

/**
 * Saturation for a single source IP over a 24-hour window.
 *
 * Tuned so the busiest attacker lands in the 90s while quieter sources spread
 * across the mid range. Set too low, every source pins at 100 and the ranking
 * stops distinguishing anything.
 */
const SOURCE_SATURATION = 1280;

/**
 * Assets absorb traffic from every source at once, so a monitored host
 * accumulates far more pressure than any individual attacker. It needs a
 * wider curve or the victim sits permanently at 100.
 */
const ASSET_SATURATION = 4000;

/** Recent pressure counts for more than pressure that has aged out. */
function recencyFactor(ageMs: number): number {
  const hours = ageMs / 3_600_000;
  if (hours < 1) return 1;
  if (hours < 2) return 0.6;
  return 0.3;
}

/** Resolved and blocked events no longer represent live exposure. */
function isOpen(event: SecurityEvent): boolean {
  return event.status === 'new' || event.status === 'investigating';
}

/**
 * Maps accumulated pressure onto a 0–100 deduction. Asymptotic so the score
 * degrades smoothly and never pins at zero from volume alone.
 */
function saturatingDeduction(pressure: number, saturation: number): number {
  return 100 * (1 - Math.exp(-pressure / saturation));
}

/**
 * Overall posture score. Higher is safer.
 *
 * Uses the severity weights from `config/severity.ts` (critical 25, high 10,
 * medium 4, low 1), decayed by age and limited to unresolved events, so
 * working the queue visibly improves the score.
 */
export function computeSecurityScore(events: SecurityEvent[], now = Date.now()): SecurityScore {
  const cutoff = now - SCORE_WINDOW_MS;
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const pressure: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const event of events) {
    if (event.timestamp < cutoff || !isOpen(event)) continue;
    counts[event.severity] += 1;
    pressure[event.severity] += SEVERITY_META[event.severity].weight * recencyFactor(now - event.timestamp);
  }

  const totalPressure = pressure.critical + pressure.high + pressure.medium + pressure.low;
  const deduction = saturatingDeduction(totalPressure, SATURATION);
  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));

  const breakdown = (Object.keys(counts) as Severity[])
    .map((severity) => ({
      severity,
      count: counts[severity],
      // Each severity's share of the total deduction, for UI transparency.
      penalty: totalPressure === 0 ? 0 : Math.round((pressure[severity] / totalPressure) * deduction),
    }))
    .filter((entry) => entry.count > 0);

  return { score, ...classifyScore(score), breakdown };
}

function classifyScore(score: number): { band: SecurityScore['band']; label: string } {
  if (score >= 80) return { band: 'good', label: 'Low Risk' };
  if (score >= 60) return { band: 'moderate', label: 'Moderate Risk' };
  if (score >= 35) return { band: 'elevated', label: 'Elevated Risk' };
  return { band: 'critical', label: 'Critical Risk' };
}

/** Total severity weight carried by a set of events. */
function totalWeight(events: SecurityEvent[]): number {
  return events.reduce((sum, event) => sum + SEVERITY_META[event.severity].weight, 0);
}

/**
 * Risk contributed by a single source IP, 0–100. Counts every event from that
 * source regardless of status — a blocked attacker is still a risky origin.
 */
export function computeSourceRisk(events: SecurityEvent[]): number {
  return Math.round(saturatingDeduction(totalWeight(events), SOURCE_SATURATION));
}

/**
 * Risk carried by a monitored asset, 0–100. Scored on a wider curve than a
 * source IP because a host aggregates pressure from every attacker at once.
 */
export function computeAssetRisk(events: SecurityEvent[]): number {
  return Math.round(saturatingDeduction(totalWeight(events), ASSET_SATURATION));
}

/** Translates a 0–100 risk number into the shared severity vocabulary. */
export function riskToSeverity(risk: number): Severity {
  if (risk >= 75) return 'critical';
  if (risk >= 50) return 'high';
  if (risk >= 25) return 'medium';
  return 'low';
}
