/**
 * The SVG filter that makes the glass actually refract.
 *
 * Apple's Liquid Glass bends the content behind a surface; plain glassmorphism
 * only blurs it. The difference is `feDisplacementMap`: a turbulence field is
 * used as a height map, and its R/G channels push the backdrop's pixels sideways,
 * which is what reads as a lens rather than a frosted pane.
 *
 * Honest scope: this is an approximation. Apple composites Liquid Glass in the
 * OS, refracting content beyond the element's own bounds, which `backdrop-filter`
 * cannot reach. And `backdrop-filter: url(#id)` is a Chromium extension, not
 * spec — see the open W3C SVG WG issue on interoperable backdrop refraction.
 * Everywhere else the `@supports` guard in index.css falls back to blur and
 * saturate, which still reads as glass, just without the edge lensing.
 */
export function LiquidGlassDefs() {
  return (
    <svg aria-hidden="true" className="pointer-events-none absolute h-0 w-0" focusable="false">
      <defs>
        {/* Panels: a wide, soft lens. */}
        <filter id="liquid-glass" x="-20%" y="-20%" width="140%" height="140%">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.008 0.012"
            numOctaves="2"
            seed="17"
            result="noise"
          >
            {/*
              This is what makes the surface read as liquid rather than as a
              static frosted pane: the height field itself morphs, so the
              refraction flows across the glass. Long duration and a
              palindromic value list (a→b→a) mean it never visibly loops or
              snaps back to the start.
            */}
            <animate
              attributeName="baseFrequency"
              dur="26s"
              values="0.008 0.012; 0.013 0.007; 0.006 0.014; 0.008 0.012"
              calcMode="spline"
              keySplines="0.4 0 0.6 1; 0.4 0 0.6 1; 0.4 0 0.6 1"
              repeatCount="indefinite"
            />
          </feTurbulence>
          <feGaussianBlur in="noise" stdDeviation="7" result="soft" />
          <feDisplacementMap
            in="SourceGraphic"
            in2="soft"
            scale="46"
            xChannelSelector="R"
            yChannelSelector="G"
          />
        </filter>

        {/* Controls: a tighter lens, so small pills do not smear. */}
        <filter id="liquid-glass-sm" x="-20%" y="-20%" width="140%" height="140%">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.02"
            numOctaves="2"
            seed="9"
            result="noise"
          >
            <animate
              attributeName="baseFrequency"
              dur="19s"
              values="0.02; 0.028; 0.016; 0.02"
              calcMode="spline"
              keySplines="0.4 0 0.6 1; 0.4 0 0.6 1; 0.4 0 0.6 1"
              repeatCount="indefinite"
            />
          </feTurbulence>
          <feGaussianBlur in="noise" stdDeviation="4" result="soft" />
          <feDisplacementMap
            in="SourceGraphic"
            in2="soft"
            scale="18"
            xChannelSelector="R"
            yChannelSelector="G"
          />
        </filter>
      </defs>
    </svg>
  );
}

/**
 * Wordmark.
 *
 * A concentric aperture inside a shield: the shield states what the product
 * guards, the iris states that it is watching. Drawn as plain geometry so it
 * stays crisp at 32px and inherits `currentColor` in both themes.
 */
export function SentinelMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      className={className}
      role="img"
      aria-label="Sentinel SOC"
      fill="none"
      stroke="currentColor"
    >
      {/* Shield silhouette */}
      <path
        d="M16 2.5 27 6.6v8.2c0 6.6-4.4 12.5-11 14.7C9.4 27.3 5 21.4 5 14.8V6.6L16 2.5Z"
        strokeWidth="1.6"
        strokeLinejoin="round"
        opacity="0.9"
      />
      {/* Aperture blades */}
      <circle cx="16" cy="15" r="6.2" strokeWidth="1.3" opacity="0.55" />
      <circle cx="16" cy="15" r="2.5" strokeWidth="1.6" />
      <path d="M16 8.8v2.4M16 18.8v2.4M9.8 15h2.4M19.8 15h2.4" strokeWidth="1.3" strokeLinecap="round" opacity="0.8" />
    </svg>
  );
}
