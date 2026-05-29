/**
 * Phase 6b — CubeLogo animation timelines
 *
 * Five GSAP timeline builders for the pyramid cube logo.
 * - Composition: pyramid (2 cubes base + 1 apex)
 * - Cube-trio role mapping:
 *     bottomLeft  → <g data-layer="cube-bottom-left">  (was: cube-front-left)
 *     bottomRight → <g data-layer="cube-bottom-right"> (was: cube-front-right)
 *     top         → <g data-layer="cube-top">          (was: cube-back-top)
 *   If your CubeLogo.tsx uses the legacy trio names, remap at the call site.
 *
 * - All motion uses `xPercent` / `yPercent` / `scale` / `rotation`, never
 *   absolute SVG units. This is the critical requirement for the timelines
 *   to work identically at 32px (header) and 96px (login hero), and at any
 *   size in between.
 *
 * - Builders are pure factory functions: same input → same timeline.
 *   No hidden global state, no side effects on import.
 *
 * - Requires: `gsap@^3` only. No GSAP plugins, no @gsap/react (you wrap
 *   the call yourself with useGSAP or useEffect — see usage example).
 *
 * Usage example (React + @gsap/react):
 *
 *     import { useGSAP } from '@gsap/react';
 *     import { buildLoaderTimeline } from './2026-05-20-phase-6b-logo-animations';
 *
 *     useGSAP(() => {
 *       const tl = buildLoaderTimeline({
 *         bottomLeft:  svgRef.current!.querySelector('[data-layer="cube-bottom-left"]')!,
 *         bottomRight: svgRef.current!.querySelector('[data-layer="cube-bottom-right"]')!,
 *         top:         svgRef.current!.querySelector('[data-layer="cube-top"]')!,
 *       }, svgRef.current!);
 *       return () => { tl.kill(); };
 *     }, { scope: svgRef });
 */

import { gsap } from "gsap";

/* ─────────────────────────────────────────────────────────────
   Types
   ───────────────────────────────────────────────────────────── */

export interface PyramidCubes {
  /** <g data-layer="cube-bottom-left"> */
  bottomLeft: SVGGElement;
  /** <g data-layer="cube-bottom-right"> */
  bottomRight: SVGGElement;
  /** <g data-layer="cube-top"> — the apex */
  top: SVGGElement;
}

export interface AnimationOpts {
  /** Multiplier on every animation duration. Default 1. */
  speed?: number;
  /** Override the error-flash colour. Default 'rgba(220, 38, 38, .85)'. */
  errorFlashColor?: string;
}

export type AnimationBuilder = (
  cubes: PyramidCubes,
  container: SVGSVGElement,
  opts?: AnimationOpts,
) => gsap.core.Timeline;

/* ─────────────────────────────────────────────────────────────
   Setup helper — must be called once per element before any
   timeline targets it. Sets transform-box so rotations pivot
   from each cube's own centre regardless of its SVG position.
   ───────────────────────────────────────────────────────────── */

export function prepareCubes(cubes: PyramidCubes): void {
  const all = [cubes.bottomLeft, cubes.bottomRight, cubes.top];
  gsap.set(all, {
    transformOrigin: "50% 50%",
    transformBox: "fill-box" as never, // not in GSAP's type for SVG, but supported
  });
}

const arr = (c: PyramidCubes): SVGGElement[] => [
  c.bottomLeft,
  c.bottomRight,
  c.top,
];

/* ─────────────────────────────────────────────────────────────
   LOADER — round-robin clockwise pulse (apex → bot-right → bot-left)
   1.5s cycle · GitLab-3-dot-spinner-in-spirit
   See: specs/2026-05-22-phase-6b-loader-spec.md
   ───────────────────────────────────────────────────────────── */

export const buildLoaderTimeline: AnimationBuilder = (
  cubes,
  _container,
  opts = {},
) => {
  const d = 1 / (opts.speed ?? 1);
  const T = 1.5 * d; // full cycle
  const slot = T / 3; // each cube's window
  const peak = slot * 0.5; // halfway is the bright peak

  // Clockwise as the viewer sees the pyramid: apex → bottom-right → bottom-left
  const ordered = [cubes.top, cubes.bottomRight, cubes.bottomLeft];
  const all = arr(cubes);

  const REST = "brightness(0.82) saturate(0.9) drop-shadow(0 0 0 transparent)";
  const PEAK =
    "brightness(1.12) saturate(1.15) drop-shadow(0 0 2px rgba(166, 190, 221, .65))";

  const tl = gsap.timeline({ repeat: -1 });
  tl.set(all, { filter: REST, scale: 1 }, 0);

  ordered.forEach((cube, i) => {
    const start = i * slot;
    tl.to(
      cube,
      { filter: PEAK, scale: 1.07, duration: peak, ease: "power2.out" },
      start,
    );
    tl.to(
      cube,
      {
        filter: REST,
        scale: 1,
        duration: slot - peak,
        ease: "power2.in",
      },
      start + peak,
    );
  });

  return tl;
};

/* ─────────────────────────────────────────────────────────────
   IDLE — counter-phase ambient breath
   4.8s loop · base inhales while apex exhales
   ───────────────────────────────────────────────────────────── */

export const buildIdleTimeline: AnimationBuilder = (
  cubes,
  _container,
  opts = {},
) => {
  const d = 1 / (opts.speed ?? 1);

  const tl = gsap.timeline({ repeat: -1, yoyo: true });
  tl.to(
    [cubes.bottomLeft, cubes.bottomRight],
    {
      yPercent: -7,
      scale: 1.02,
      duration: 2.4 * d,
      ease: "sine.inOut",
      stagger: { each: 0.5 * d },
    },
    0,
  );
  tl.to(
    cubes.top,
    {
      yPercent: 5,
      scale: 0.99,
      duration: 2.4 * d,
      ease: "sine.inOut",
    },
    0,
  );
  return tl;
};

/* ─────────────────────────────────────────────────────────────
   ERROR — flash + decaying shake + droop
   2.4s loop including a 0.9s hold before repeat
   ───────────────────────────────────────────────────────────── */

export const buildErrorTimeline: AnimationBuilder = (
  cubes,
  container,
  opts = {},
) => {
  const d = 1 / (opts.speed ?? 1);
  const cs = arr(cubes);
  const flashColor = opts.errorFlashColor ?? "rgba(220, 38, 38, .85)";

  const tl = gsap.timeline({ repeat: -1 });

  // 1. Red drop-shadow flash on the container SVG
  tl.fromTo(
    container,
    { filter: "none" },
    {
      filter: `drop-shadow(0 0 5px ${flashColor})`,
      duration: 0.1 * d,
      yoyo: true,
      repeat: 1,
    },
    0,
  );

  // 2. Decaying horizontal shake with paired rotation.
  //    xPercent values are relative to each cube's own width.
  tl.to(
    cs,
    {
      keyframes: [
        { xPercent: -12, rotation: -3, duration: 0.06 * d },
        { xPercent: 12, rotation: 3, duration: 0.08 * d },
        { xPercent: -10, rotation: -2, duration: 0.08 * d },
        { xPercent: 10, rotation: 2, duration: 0.08 * d },
        { xPercent: -6, rotation: -1, duration: 0.08 * d },
        { xPercent: 5, rotation: 0.5, duration: 0.08 * d },
        { xPercent: 0, yPercent: 4, duration: 0.16 * d }, // droop
        { xPercent: 0, yPercent: 0, duration: 0.4 * d }, // recover
      ],
      ease: "power2.out",
      stagger: 0.04 * d,
    },
    0.02 * d,
  );

  // 3. Hold before repeat
  tl.to({}, { duration: 0.9 * d });
  return tl;
};

/* ─────────────────────────────────────────────────────────────
   NOTFOUND — apex slot is empty (dashed ghost pulses in its place)
   3.2s loop · "actually says 'not found'"

   Required SVG structure inside `container`:
     <g data-layer="cube-top">
       <g class="cube-logo__cube">… apex faces …</g>
       <polygon data-ghost-slot … opacity="0"/>   ← pulses in
     </g>

   The baseline SVG shipped with this spec already includes the ghost slot.
   If the slot is missing the timeline still runs (apex just fades in/out
   with no visible placeholder).
   ───────────────────────────────────────────────────────────── */

export const buildNotfoundTimeline: AnimationBuilder = (
  cubes,
  container,
  opts = {},
) => {
  const d = 1 / (opts.speed ?? 1);
  // Total period 4.2s (was 3.2s) — extends the "three whole cubes
  // resting" beat between cycles so the viewer reads the pyramid as
  // present-then-missing-then-present, not as constant motion.
  const T = 4.2 * d;

  const ghostSlot = container.querySelector<SVGElement>("[data-ghost-slot]");
  const ghostQ = container.querySelector<SVGElement>("[data-ghost-q]");

  const tl = gsap.timeline({ repeat: -1 });

  // Apex: visible → fades out & shrinks → empty hold → springs back in.
  // Matches the preview spec's `cubic-bezier(.5, .05, .5, 1)` lazy S-curve
  // so the fade reads less mechanical than power2's eased acceleration.
  const lazyS = "cubic-bezier(.5, .05, .5, 1)";
  tl.set(cubes.top, { opacity: 1, scale: 1 }, 0);
  tl.to(
    cubes.top,
    {
      opacity: 0,
      scale: 0.85,
      duration: T * 0.12,
      ease: lazyS,
    },
    T * 0.1,
  );
  tl.to(
    cubes.top,
    {
      opacity: 1,
      scale: 1.08,
      duration: T * 0.08,
      ease: lazyS,
    },
    T * 0.8,
  );
  tl.to(
    cubes.top,
    {
      scale: 1,
      duration: T * 0.12,
      ease: lazyS,
    },
    T * 0.88,
  );

  // Ghost dashed outline: pulses in, holds at 0.55 opacity, pulses out
  if (ghostSlot) {
    tl.set(ghostSlot, { opacity: 0 }, 0);
    tl.to(
      ghostSlot,
      {
        opacity: 0.55,
        duration: T * 0.12,
        ease: lazyS,
      },
      T * 0.1,
    );
    tl.to(
      ghostSlot,
      {
        opacity: 0,
        duration: T * 0.12,
        ease: lazyS,
      },
      T * 0.76,
    );
  }

  // "?" glyph inside the ghost slot — fades in with a tiny upward drift
  // ("0 → 1" question), then fades out as the apex springs back. Timing
  // tracks the ghost-slot pulse so the two read as one "missing piece".
  if (ghostQ) {
    tl.set(ghostQ, { opacity: 0, yPercent: 15 }, 0);
    tl.to(
      ghostQ,
      {
        opacity: 1,
        yPercent: 0,
        duration: T * 0.14,
        ease: lazyS,
      },
      T * 0.18,
    );
    tl.to(
      ghostQ,
      {
        opacity: 0,
        yPercent: -15,
        duration: T * 0.14,
        ease: lazyS,
      },
      T * 0.72,
    );
  }

  // Base cubes: barely-there breath so the pyramid never feels frozen.
  // Preview uses `translateY(.4px)` ≈ 0.7% of cube height; using 2% here
  // looked too bouncy ("the base is dancing under the missing apex").
  tl.to(
    [cubes.bottomLeft, cubes.bottomRight],
    {
      yPercent: 0.7,
      duration: T * 0.5,
      ease: "sine.inOut",
      yoyo: true,
      repeat: 1,
    },
    0,
  );

  // Pin total loop duration
  tl.to({}, { duration: 0 }, T);

  return tl;
};

/* ─────────────────────────────────────────────────────────────
   CRASH — wobble → apex tips first → base topples → reset
   3.6s loop + 0.3s pause between repeats
   ───────────────────────────────────────────────────────────── */

export const buildCrashTimeline: AnimationBuilder = (
  cubes,
  _container,
  opts = {},
) => {
  const d = 1 / (opts.speed ?? 1);
  const cs = arr(cubes);

  const tl = gsap.timeline({ repeat: -1, repeatDelay: 0.3 * d });

  // Pre-fall wobble — three quick oscillations across the whole pyramid
  tl.to(cs, {
    rotation: 3,
    duration: 0.1 * d,
    yoyo: true,
    repeat: 3,
    ease: "power2.inOut",
    stagger: 0.04 * d,
  });

  // Sequential fall — apex first (top of the pyramid topples),
  // then base cubes collapse outward and downward.
  // yPercent: 150 ≈ off-canvas at any size; xPercent ±70 ≈ aside.
  const fallSequence: Array<
    [SVGGElement, { x: number; y: number; rot: number }]
  > = [
    [cubes.top, { x: -3, y: 150, rot: -200 }],
    [cubes.bottomLeft, { x: -75, y: 160, rot: 220 }],
    [cubes.bottomRight, { x: 75, y: 180, rot: 40 }],
  ];

  fallSequence.forEach(([cube, p], i) => {
    tl.to(
      cube,
      {
        xPercent: p.x,
        yPercent: p.y,
        rotation: p.rot,
        opacity: 0,
        duration: 0.9 * d,
        ease: "power3.in",
      },
      `>-${(0.65 - i * 0.05) * d}`,
    );
  });

  // Hold empty, then fade back to start
  tl.to(
    cs,
    {
      xPercent: 0,
      yPercent: 0,
      rotation: 0,
      opacity: 1,
      duration: 0.5 * d,
      ease: "power2.out",
    },
    `+=${0.4 * d}`,
  );

  return tl;
};

/* ─────────────────────────────────────────────────────────────
   Convenience map — used by the React component's switch
   ───────────────────────────────────────────────────────────── */

export const TIMELINE_BUILDERS = {
  loader: buildLoaderTimeline,
  idle: buildIdleTimeline,
  error: buildErrorTimeline,
  notfound: buildNotfoundTimeline,
  crash: buildCrashTimeline,
} as const;

export type AnimationMode = keyof typeof TIMELINE_BUILDERS;
