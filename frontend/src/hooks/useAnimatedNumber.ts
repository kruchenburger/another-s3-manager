import { useEffect, useRef, useState } from "react";

/** Animates numeric changes with an ease-out count-up/down (~500ms rAF).
 * No animation on mount (starts at the initial value) and none under
 * prefers-reduced-motion — the value just snaps. Used by the object
 * counter in BucketPageHeader so Load more "runs" 50 → 100 instead of
 * flipping. */
export function useAnimatedNumber(value: number): number {
  const [display, setDisplay] = useState(value);
  // Animate FROM the currently displayed value, not the previous target —
  // otherwise a value change arriving mid-animation makes the counter snap
  // to the old target before running toward the new one.
  const displayRef = useRef(value);

  useEffect(() => {
    const from = displayRef.current;
    if (from === value) return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches) {
      setDisplay(value);
      displayRef.current = value;
      return;
    }
    const start = performance.now();
    const DURATION = 500;
    let raf = 0;
    const tick = (now: number) => {
      // Clamp BOTH ends. A rAF callback receives the timestamp of the frame's
      // start, which can precede the performance.now() captured just above —
      // making `now - start` negative on the first tick. Without a lower
      // clamp, `t < 0` sends `eased` negative too, so the interpolated value
      // overshoots PAST `from` to the wrong side of the animation. Each new
      // target restarts the animation from displayRef.current (see comment
      // above), so during a "Load all" drain — which restarts this effect on
      // every arriving chunk, potentially thousands of times back-to-back — a
      // tiny per-tick overshoot compounds restart after restart into a wildly
      // wrong (and possibly deeply negative) displayed number. Clamping
      // t to [0, 1] keeps eased in [0, 1], which keeps the interpolated value
      // mathematically confined to [from, value] (or [value, from] when
      // counting down) — it can never leave that interval, so it can never
      // overshoot and never compound.
      const t = Math.min(1, Math.max(0, (now - start) / DURATION));
      const eased = 1 - (1 - t) ** 3;
      const next = Math.round(from + (value - from) * eased);
      setDisplay(next);
      displayRef.current = next;
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  return display;
}
