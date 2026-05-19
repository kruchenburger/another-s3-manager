import type { ReactNode } from "react";
import { AutoCloseProgress } from "@/components/Upload/AutoCloseProgress";

interface MessageWithTimerProps {
  children: ReactNode;
  /** Same value passed to Mantine's `autoClose` on the parent notification.
   *  Pass `false` or `0` to render the message without a timer indicator. */
  autoCloseMs: number | false;
}

/**
 * Wraps a Mantine notification's `message` content with a thin shrinking bar
 * at the bottom that visualises the remaining time until the toast
 * auto-dismisses. The bar inherits the toast's text colour so it stays
 * subtle across success/warning/error colour variants.
 *
 * Drop-in replacement for a plain string or ReactNode `message`:
 *
 *   notifications.show({
 *     message: <MessageWithTimer autoCloseMs={5000}>Deleted</MessageWithTimer>,
 *     autoClose: 5000,
 *   });
 *
 * For `autoCloseMs={false}` (or 0) renders just the children — no bar — so
 * a single callsite can dynamically toggle the indicator (e.g. error toasts
 * with `autoClose: false` skip the bar by passing the same false through).
 */
export function MessageWithTimer({ children, autoCloseMs }: MessageWithTimerProps) {
  const showBar = typeof autoCloseMs === "number" && autoCloseMs > 0;

  if (!showBar) {
    return <>{children}</>;
  }

  return (
    <div style={{ position: "relative", paddingBottom: 6 }}>
      {children}
      <AutoCloseProgress durationMs={autoCloseMs} />
    </div>
  );
}
