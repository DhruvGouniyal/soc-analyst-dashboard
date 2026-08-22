import { useEffect, useState } from 'react';

/**
 * A ticking timestamp.
 *
 * Relative ages ("4 sec ago") would otherwise go stale between event arrivals.
 * The interval is a parameter so the header can tick every second while denser
 * panels tick slowly, rather than re-rendering the whole dashboard at 1 Hz.
 */
export function useClock(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);

  return now;
}
