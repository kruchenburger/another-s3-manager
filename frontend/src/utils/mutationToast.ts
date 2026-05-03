import { notifications } from "@mantine/notifications";
import { getErrorMessage } from "@/utils/apiError";

interface MutationLike<TArgs> {
  mutate: (
    args: TArgs,
    opts?: { onSuccess?: () => void; onError?: (e: unknown) => void },
  ) => void;
}

/**
 * Run a TanStack Query mutation with conventional admin-page UX:
 *   - green toast with `successMessage` on success
 *   - red toast with `getErrorMessage(error)` on failure
 *   - optional `onSuccess` callback (typically modal close + state cleanup)
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
      notifications.show({ message: successMessage, color: "green" });
      onSuccess?.();
    },
    onError: (e) => {
      // autoClose: false — error toasts default-disappear in 4s which is too
      // fast to read, especially when the message is long or the user is
      // mid-action. The user dismisses manually via the X.
      notifications.show({
        title: "Error",
        message: getErrorMessage(e),
        color: "red",
        autoClose: false,
      });
    },
  });
}
