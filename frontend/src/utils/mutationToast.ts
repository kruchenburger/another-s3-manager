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
      // Default Mantine autoClose (~4s): success messages are short and
      // disposable; the table refresh is the real confirmation.
      notifications.show({
        title: "Success",
        message: successMessage,
        color: "green",
      });
      onSuccess?.();
    },
    onError: (e) => {
      // autoClose: false — error toasts must stay until dismissed; the
      // user often needs the text to take corrective action.
      notifications.show({
        title: "Error",
        message: getErrorMessage(e),
        color: "red",
        autoClose: false,
      });
    },
  });
}
