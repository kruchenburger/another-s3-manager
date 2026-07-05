import "./AutoCloseProgress.css";

interface AutoCloseProgressProps {
  /** Duration of the bar's shrink in milliseconds. Should match the parent
   *  notification's autoClose so the bar empties when the toast dismisses. */
  durationMs: number;
}

/**
 * A 2px bar along the bottom edge of the toast that shrinks from full width
 * to zero over `durationMs` purely via CSS keyframe animation — no React
 * state, no useEffect, no re-renders.
 *
 * Earlier attempts used `useState` + double-rAF to transition from
 * scaleX(1) to scaleX(0). That subtly broke Mantine's autoClose timing
 * because the internal `setState` inside the message body caused
 * notification stack re-renders at unexpected moments, and the
 * Mantine NotificationContainer's `useEffect([autoCloseDuration])` cleanup
 * fired earlier than the configured 10s. Going back to a pure CSS
 * keyframes animation isolates this component from React's render cycle
 * entirely — the bar shrinks in the browser compositor and the React tree
 * stays stable.
 *
 * Sync caveat: the animation start is the AutoCloseProgress mount time,
 * while Mantine's autoClose timer starts on its own useEffect dep change.
 * They are NOT mechanically linked. Across stacked toasts the bars may
 * visually desync from their toast's actual dismissal time. Hovering a
 * toast pauses Mantine's setTimeout but the bar keeps shrinking. Accepted —
 * the bar is a decorative hint, not authoritative; the X button is the
 * source of truth for "I want this gone now".
 */
export function AutoCloseProgress({ durationMs }: AutoCloseProgressProps) {
  return (
    <div
      aria-hidden="true"
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        bottom: 0,
        height: 2,
        backgroundColor: "currentColor",
        opacity: 0.35,
        transformOrigin: "left center",
        // Animation handles the shrink entirely on the compositor — no
        // setState here means no React re-renders inside the toast body
        // while the bar shrinks.
        animation: `autocloseProgressShrink ${durationMs}ms linear forwards`,
        pointerEvents: "none",
      }}
    />
  );
}
