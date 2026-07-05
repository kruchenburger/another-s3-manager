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
  displayRef.current = display;

  useEffect(() => {
    const from = displayRef.current;
    if (from === value) return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches) {
      setDisplay(value);
      return;
    }
    const start = performance.now();
    const DURATION = 500;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / DURATION);
      const eased = 1 - (1 - t) ** 3;
      setDisplay(Math.round(from + (value - from) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  return display;
}
