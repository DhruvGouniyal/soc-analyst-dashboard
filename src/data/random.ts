/**
 * Seeded pseudo-random helpers.
 *
 * The historical backfill uses a fixed seed so the dashboard shows the same
 * 24 hours on every reload — a moving target makes demos and screenshots
 * unreproducible, and "random nonsense" is exactly what we want to avoid.
 * The live stream uses an unseeded instance so it stays unpredictable.
 */

/** mulberry32 — small, fast, good enough for presentation data. */
export function createRng(seed: number): () => number {
  let a = seed >>> 0;
  return function next(): number {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type Rng = () => number;

export function randomInt(rng: Rng, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

export function pick<T>(rng: Rng, items: readonly T[]): T {
  if (items.length === 0) throw new Error('pick() called with an empty list');
  return items[Math.floor(rng() * items.length)]!;
}

/** Picks an item using relative weights. Heavier weight = more frequent. */
export function weightedPick<T>(rng: Rng, entries: readonly (readonly [T, number])[]): T {
  const total = entries.reduce((sum, [, weight]) => sum + weight, 0);
  let roll = rng() * total;
  for (const [value, weight] of entries) {
    roll -= weight;
    if (roll <= 0) return value;
  }
  return entries[entries.length - 1]![0];
}

/** Clamps a value into an inclusive range. */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/** Random walk used to drift host CPU/memory without wild jumps. */
export function drift(rng: Rng, current: number, magnitude: number, min: number, max: number): number {
  const delta = (rng() - 0.5) * 2 * magnitude;
  return clamp(Math.round(current + delta), min, max);
}
