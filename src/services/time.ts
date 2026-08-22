/** Time formatting shared across panels, so relative ages read consistently. */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** `2 sec ago`, `4 min ago`, `3 hr ago`, `2 d ago`. */
export function relativeTime(timestamp: number, now = Date.now()): string {
  const delta = Math.max(0, now - timestamp);
  if (delta < 5000) return 'just now';
  if (delta < MINUTE) return `${Math.floor(delta / 1000)} sec ago`;
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)} min ago`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)} hr ago`;
  return `${Math.floor(delta / DAY)} d ago`;
}

/** `11:41:02` — the precise form used in tables and detail panels. */
export function clockTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('en-GB', { hour12: false });
}

/** `11:41` — compact form for chart axes. */
export function shortTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/** `Mon 14:00` — used when a range spans multiple days. */
export function dayAndTime(timestamp: number): string {
  const d = new Date(timestamp);
  const day = d.toLocaleDateString('en-US', { weekday: 'short' });
  return `${day} ${String(d.getHours()).padStart(2, '0')}:00`;
}

/** `2026-08-22 11:41:02` — unambiguous form for the detail panel. */
export function fullTimestamp(timestamp: number): string {
  const d = new Date(timestamp);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** Compact large counts: `4,821` stays exact, `12.4k` above five digits. */
export function formatCount(value: number): string {
  if (value >= 100_000) return `${(value / 1000).toFixed(1)}k`;
  return value.toLocaleString('en-US');
}
