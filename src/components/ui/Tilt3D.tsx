import { motion, useMotionValue, useSpring, useTransform, useReducedMotion } from 'motion/react';
import type { PointerEvent, ReactNode } from 'react';

interface Tilt3DProps {
  children: ReactNode;
  className?: string;
  /** Maximum rotation in degrees at the card's edge. */
  amplitude?: number;
  /** Scale applied while the pointer is over the card. */
  scaleOnHover?: number;
}

/**
 * Real 3D perspective tilt.
 *
 * The pointer drives Motion values directly — never React state. A `useState`
 * here would re-render the whole subtree on every mousemove and collapse the
 * frame rate the moment the event feed is also streaming; motion values are
 * written outside the render cycle and composited on the GPU.
 *
 * Springs are over-damped on purpose. A card that wobbles past its angle and
 * oscillates back reads as a toy; Apple's 3D surfaces track the finger and
 * stop. The parent supplies the perspective via `.stage-3d`, so the rotation
 * is a true projection rather than a skew.
 */
export function Tilt3D({ children, className, amplitude = 9, scaleOnHover = 1.02 }: Tilt3DProps) {
  const reduce = useReducedMotion();

  const spring = { damping: 28, stiffness: 210, mass: 0.7 };
  const rx = useSpring(useMotionValue(0), spring);
  const ry = useSpring(useMotionValue(0), spring);
  const scale = useSpring(useMotionValue(1), spring);

  // -0.5..0.5 across the card, mapped to degrees.
  const rotateX = useTransform(rx, (v) => `${v * -amplitude}deg`);
  const rotateY = useTransform(ry, (v) => `${v * amplitude}deg`);

  function handleMove(e: PointerEvent<HTMLDivElement>) {
    if (reduce) return;
    const rect = e.currentTarget.getBoundingClientRect();
    rx.set((e.clientY - rect.top) / rect.height - 0.5);
    ry.set((e.clientX - rect.left) / rect.width - 0.5);
  }

  function handleLeave() {
    rx.set(0);
    ry.set(0);
    scale.set(1);
  }

  if (reduce) return <div className={className}>{children}</div>;

  return (
    <motion.div
      className={`tilt-3d ${className ?? ''}`}
      style={{ rotateX, rotateY, scale }}
      onPointerMove={handleMove}
      onPointerEnter={() => scale.set(scaleOnHover)}
      onPointerLeave={handleLeave}
    >
      {children}
    </motion.div>
  );
}
