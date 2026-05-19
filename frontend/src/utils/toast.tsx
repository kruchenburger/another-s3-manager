import { notifications } from "@mantine/notifications";
import type { NotificationData } from "@mantine/notifications";
import { MessageWithTimer } from "@/components/Notifications/MessageWithTimer";

/** Standard toast lifetimes for the app. Use these instead of arbitrary
 *  millisecond numbers so all toasts dismiss on a consistent rhythm:
 *
 *   - `success`: 5s — short confirmation, the affected UI state is the real
 *     proof of success
 *   - `error`: 10s — long enough to read an error message
 *   - `infoLong`: 6s — when an informational toast needs to be read carefully
 *     (e.g. "URL copied, expires at 17:42")
 */
export const TOAST_DURATIONS = {
  success: 5000,
  error: 10000,
  infoLong: 6000,
} as const;

type AutoClose = number | false;

interface ToastOptions extends Omit<NotificationData, "autoClose" | "message"> {
  message: NotificationData["message"];
  /** Lifetime in ms, or `false` to keep until manually dismissed. When a
   *  number, the toast renders the AutoCloseProgress bar along its bottom
   *  edge so the user can see how long is left. */
  autoClose?: AutoClose;
}

/**
 * Show a Mantine notification with a bottom-edge auto-close timer bar.
 *
 * Thin wrapper around `notifications.show` that:
 *   1. Wraps the `message` content in `<MessageWithTimer>` so the bar appears
 *      under any toast that has a numeric `autoClose`
 *   2. Defaults `autoClose` to 5s when omitted (instead of Mantine's
 *      undocumented 4s default) so the timing matches our success-toast convention
 *   3. Skips the bar when `autoClose: false` so persistent toasts don't show
 *      a misleading shrinking strip that never reaches zero
 *
 * Falls back to plain text rendering when the `message` is a string — the
 * wrapper only adds the bar element below the existing content, no other
 * styling is applied.
 */
export function showToast(options: ToastOptions): string {
  const autoClose = options.autoClose ?? TOAST_DURATIONS.success;
  return notifications.show({
    ...options,
    autoClose,
    message: <MessageWithTimer autoCloseMs={autoClose}>{options.message}</MessageWithTimer>,
  });
}
