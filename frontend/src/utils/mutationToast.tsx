import { notifications } from "@mantine/notifications";
import { getErrorMessage } from "@/utils/apiError";
import { MessageWithTimer } from "@/components/Notifications/MessageWithTimer";

/** Default toast lifetimes used by the upload progress flow and the admin
 *  mutation helper. Kept here so all auto-close behaviour in the app stays
 *  consistent — successes dismiss quickly (the affected row in the table is
 *  the real confirmation), failures linger long enough to be read. */
export const TOAST_DURATIONS = {
  success: 5000,
  error: 10000,
} as const;

interface MutationLike<TArgs> {
  mutate: (
    args: TArgs,
    opts?: { onSuccess?: () => void; onError?: (e: unknown) => void },
  ) => void;
}

/**
 * Run a TanStack Query mutation with conventional admin-page UX:
 *   - green toast with `successMessage` on success (5s autoClose)
 *   - red toast with `getErrorMessage(error)` on failure (10s autoClose)
 *   - optional `onSuccess` callback (typically modal close + state cleanup)
 *
 * Both toasts render the AutoCloseProgress bar along their bottom edge so
 * the user has a visible hint of when the toast will dismiss.
 *
 * Replaces 12-line `mutate({...}, { onSuccess: ..., onError: ... })` blocks
 * with a single line, keeping the call sites scannable.
 */
export function runWithToasts<TArgs>(
  mutation: MutationLike<TArgs>,
  args: TArgs,
  successMessage: string,
  onSuccess?: () => void,
): void {
  mutation.mutate(args, {
    onSuccess: () => {
      notifications.show({
        title: "Success",
        message: (
          <MessageWithTimer autoCloseMs={TOAST_DURATIONS.success}>
            {successMessage}
          </MessageWithTimer>
        ),
        color: "green",
        autoClose: TOAST_DURATIONS.success,
      });
      onSuccess?.();
    },
    onError: (e) => {
      notifications.show({
        title: "Error",
        message: (
          <MessageWithTimer autoCloseMs={TOAST_DURATIONS.error}>
            {getErrorMessage(e)}
          </MessageWithTimer>
        ),
        color: "red",
        autoClose: TOAST_DURATIONS.error,
      });
    },
  });
}
