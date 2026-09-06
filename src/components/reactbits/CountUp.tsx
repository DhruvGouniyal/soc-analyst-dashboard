import { useMotionValue, useSpring } from 'motion/react';
import { useCallback, useEffect, useRef } from 'react';

/**
 * CountUp — adapted from React Bits (MIT).
 *
 * Upstream gates the animation behind `useInView({ once: true })`, so the number
 * animates a single time when it scrolls into view. These KPIs change on every
 * metric tick, so that version would animate once and then snap for the rest of
 * the session. Here the spring simply tracks `to`: every change is interpolated,
 * which is also what makes a live console feel calm instead of twitchy.
 *
 * The spring is deliberately over-damped (no overshoot). A KPI that bounces past
 * its value and settles back reads as decorative; Apple reserves overshoot for
 * direct manipulation, not for data.
 */
interface CountUpProps {
  to: number;
  /** Seconds. Longer = softer settle. */
  duration?: number;
  separator?: string;
  className?: string;
}

export default function CountUp({
  to,
  duration = 1.1,
  separator = ',',
  className = '',
}: CountUpProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const motionValue = useMotionValue(to);

  const springValue = useSpring(motionValue, {
    damping: 20 + 40 * (1 / duration),
    stiffness: 100 * (1 / duration),
  });

  const format = useCallback(
    (latest: number) => {
      const rounded = Math.round(latest);
      const formatted = Intl.NumberFormat('en-US', { useGrouping: !!separator }).format(rounded);
      return separator ? formatted.replace(/,/g, separator) : formatted;
    },
    [separator],
  );

  // Re-target the spring whenever the underlying metric moves.
  useEffect(() => {
    motionValue.set(to);
  }, [motionValue, to]);

  useEffect(() => {
    // Paint the initial value immediately so the first frame is never blank.
    if (ref.current) ref.current.textContent = format(springValue.get());
    const unsubscribe = springValue.on('change', (latest: number) => {
      if (ref.current) ref.current.textContent = format(latest);
    });
    return () => unsubscribe();
  }, [springValue, format]);

  return <span className={className} ref={ref} aria-label={String(to)} />;
}
