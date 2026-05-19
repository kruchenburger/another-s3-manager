import { Box } from "@mantine/core";
import classes from "./AutoCloseProgress.module.css";

interface AutoCloseProgressProps {
  /** Duration of the bar's fill animation in milliseconds. Should match the
   *  `autoClose` value on the parent Mantine notification so the bar empties
   *  exactly when the toast disappears. */
  durationMs: number;
}

/**
 * A 2px-thin bar that animates from 100% width to 0% over `durationMs`,
 * sitting at the bottom of a notification's message body to indicate when
 * the toast will auto-dismiss.
 *
 * Mantine notifications don't expose a built-in timer indicator — autoClose
 * is implemented as a plain setTimeout. Hovering a toast pauses the timer
 * (Mantine's NotificationContainer cancels the timeout on mouseEnter), but
 * the animation here keeps running, so the bar may briefly desync from the
 * actual remaining time on hover. Accepted trade-off: the visual hint that
 * "this toast is on a timer" is more valuable than millisecond accuracy.
 */
export function AutoCloseProgress({ durationMs }: AutoCloseProgressProps) {
  return (
    <Box
      className={classes.bar}
      style={{ animationDuration: `${durationMs}ms` }}
      role="presentation"
    />
  );
}
