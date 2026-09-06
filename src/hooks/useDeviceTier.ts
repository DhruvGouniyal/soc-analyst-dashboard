import { useEffect, useState } from 'react';

export type DeviceTier = 'high' | 'medium' | 'low';

/**
 * What each tier turns off, in cost order:
 *
 *   high    everything: shader, swarm cursor, grain, glass on every surface
 *   medium  shader at reduced resolution, no cursor WebGL, glass kept on chrome
 *           but data panels go opaque (backdrop-filter is the dominant cost)
 *   low     no WebGL at all, no grain, no blur anywhere — flat opaque surfaces
 *
 * Nothing about legibility or function changes between tiers. Only decoration
 * is removed, so the console is identical to work with on a Chromebook and on a
 * workstation.
 */
const SOFTWARE_GL = /swiftshader|llvmpipe|software|basic render|microsoft basic/i;

const VALID: DeviceTier[] = ['high', 'medium', 'low'];

/**
 * `?quality=high|medium|low` pins the tier and disables auto-demotion.
 *
 * Auto-detection is right for real users but wrong for a demo: presenting on an
 * unfamiliar machine, or capturing footage, you want the full treatment even if
 * the heuristics would hedge. This is the escape hatch.
 */
function forcedTier(): DeviceTier | null {
  if (typeof window === 'undefined') return null;
  const q = new URLSearchParams(window.location.search).get('quality');
  return VALID.includes(q as DeviceTier) ? (q as DeviceTier) : null;
}

/** One-shot capability probe. Cheap: no rendering, just capability strings. */
function probeStaticTier(): DeviceTier {
  if (typeof window === 'undefined') return 'medium';

  const forced = forcedTier();
  if (forced) return forced;

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return 'low';

  const cores = navigator.hardwareConcurrency ?? 4;
  // Non-standard but widely available on Chromium, which is where the heavy
  // effects actually run. Absent elsewhere, so it only ever downgrades.
  const memory = (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? 8;

  /*
   * Software rendering is the single most important signal and the easiest to
   * miss. A machine with no GPU acceleration reports plenty of cores and memory
   * but cannot composite a full-screen shader plus stacked backdrop blurs at
   * any usable frame rate. Checking the renderer string catches it up front
   * instead of shipping a 3 FPS page and hoping the FPS probe saves it.
   */
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') as WebGLRenderingContext | null;
    if (!gl) return 'low';
    const info = gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : '';
    if (renderer && SOFTWARE_GL.test(renderer)) return 'low';
  } catch {
    return 'low';
  }

  if (cores <= 2 || memory <= 2) return 'low';
  if (cores <= 4 || memory <= 4) return 'medium';
  return 'high';
}

/**
 * Device tier, refined by what the machine actually achieves.
 *
 * The static probe reads capability; the frame sampler reads reality. Hardware
 * strings routinely lie — a thermally throttled laptop, a busy tab, or an
 * external 4K display all produce a machine that benchmarks "high" and then
 * drops frames. Sampling once after mount and demoting on a bad result is what
 * makes this hold up on hardware the probe has never seen.
 */
export function useDeviceTier(): DeviceTier {
  const [tier, setTier] = useState<DeviceTier>(probeStaticTier);

  useEffect(() => {
    // A pinned tier must stay pinned, or the sampler would undo it.
    if (forcedTier() || tier === 'low') return;

    let frames = 0;
    let raf = 0;
    const start = performance.now();

    const sample = () => {
      frames += 1;
      const elapsed = performance.now() - start;
      if (elapsed < 2000) {
        raf = requestAnimationFrame(sample);
        return;
      }
      const fps = frames / (elapsed / 1000);
      // Demote only. Promoting on a good sample would let the page oscillate
      // between tiers as load changes, which is worse than being conservative.
      if (fps < 24) setTier('low');
      else if (fps < 45) setTier((t) => (t === 'high' ? 'medium' : t));
    };

    raf = requestAnimationFrame(sample);
    return () => cancelAnimationFrame(raf);
    // Runs once per tier value; a demotion re-samples at the new tier.
  }, [tier]);

  return tier;
}
