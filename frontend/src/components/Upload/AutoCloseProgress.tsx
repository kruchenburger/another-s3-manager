import { useEffect, useState } from "react";
import { Progress } from "@mantine/core";

interface AutoCloseProgressProps {
  /** Duration of the bar's fill animation in milliseconds. Should match the
   *  `autoClose` value on the parent Mantine notification so the bar empties
   *  exactly when the toast disappears. */
  durationMs: number;
}

/**
 * A thin bar that animates from 100% to 0% over `durationMs`, sitting at the
 * bottom of a notification's message body to indicate when the toast will
 * auto-dismiss.
 *
 * Implementation: a Mantine `<Progress>` whose `value` snaps from 100 to 0
 * inside a `useEffect`. Mantine applies its own CSS transition on the inner
 * bar (`width` transition with a curve), and we override `transitionDuration`
 * via inline style so it stretches over the full `durationMs`. The single
 * value snap (not a per-tick `setInterval`) means zero re-renders during the
 * animation — the browser handles it on the compositor.
 *
 * Why this shape instead of a hand-rolled CSS keyframes animation: keyframes
 * + CSS modules scoping was fragile in production (bar invisible despite the
 * keyframe being emitted into the bundle). Mantine's Progress with a CSS
 * transition has consistent rendering across all our supported browsers.
 *
 * Mantine notifications don't expose a built-in timer indicator — `autoClose`
 * is a plain setTimeout. Hovering a toast pauses Mantine's timer but this
 * bar keeps shrinking; the two may briefly desync on hover. Accepted —
 * the visual hint that "this toast is on a timer" is worth more than
 * millisecond accuracy.
 */
export function AutoCloseProgress({ durationMs }: AutoCloseProgressProps) {
  // Start at 100% on mount, snap to 0% on the next paint so the transition
  // takes full `durationMs`. The double rAF guarantees the initial 100% is
  // painted before we change the value — without it, React batches the
  // initial render and the setState, and the transition starts from 0%.
  const [value, setValue] = useState(100);

  useEffect(() => {
    const id = requestAnimationFrame(() => {
      requestAnimationFrame(() => setValue(0));
    });
    return () => cancelAnimationFrame(id);
  }, [durationMs]);

  return (
    <Progress
      value={value}
      size="xs"
      color="gray"
      radius="xs"
      transitionDuration={durationMs}
      mt="xs"
      role="presentation"
    />
  );
}
