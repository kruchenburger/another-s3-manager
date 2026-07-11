import {
  ActionIcon,
  Group,
  Progress,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import { X } from "lucide-react";

export interface UploadProgressItem {
  name: string;
  /** "finalizing" = the body is fully sent (100%) and the server is spooling
   *  it to a temp file + streaming to S3 (managed multipart) before replying —
   *  a tens-of-seconds gap on multi-GB files. Rendered as "Finalizing on
   *  server…" so the bar doesn't look frozen at 100%. */
  status: "pending" | "uploading" | "finalizing" | "done" | "error" | "cancelled";
  error?: string;
  /** 0..100 percent of THIS file's body uploaded. Only meaningful while
   *  status === "uploading". Defaults to 0 until the browser fires the first
   *  progress event. */
  progress?: number;
}

interface UploadProgressProps {
  items: UploadProgressItem[];
  /** Abort the in-flight upload and stop the loop. Wired to the "X" button
   *  while a file is still transferring (status "uploading"). Omit to hide the
   *  button (e.g. the final-summary state where there's nothing to cancel). */
  onCancel?: () => void;
  /** Dismiss the toast WITHOUT aborting. Wired to the "X" button once the file
   *  is "finalizing": the body is already on the server, so cancelling can't
   *  stop the S3 write anymore (it would only desync the UI into "cancelled"
   *  while the file actually lands). Closing just hides the toast; the upload
   *  finishes on the server in the background. */
  onDismiss?: () => void;
}

/**
 * Smooth, single-bar progress for a batched upload.
 *
 * Two display modes by batch size:
 *
 *   1. Single-file batch (total === 1): the bar fills with the file's own
 *      byte-level upload percentage. The user sees the filename + a moving
 *      bar — no "0/1" counter (it would just sit at 0 until the file finishes,
 *      which is exactly the "looks frozen" UX complaint).
 *
 *   2. Multi-file batch (total > 1): the bar fills smoothly with
 *      "files-fully-done plus the current file's fractional progress" instead
 *      of jumping in discrete steps at each file boundary. For a 224-file
 *      batch with 100 done and the 101st at 50%, the bar reads
 *      (100 + 0.5) / 224 ≈ 44.9%. The counter still shows "100/224" so the
 *      user can read both the rate of file completions AND the smoothness of
 *      transfer.
 *
 * The cancel button is rendered next to the counter so it's easy to find
 * during a long batch; clicking it aborts the in-flight XHR via the consumer's
 * AbortController and stops subsequent files in the loop from starting.
 */
export function UploadProgress({ items, onCancel, onDismiss }: UploadProgressProps) {
  const total = items.length;
  const done = items.filter((i) => i.status === "done").length;
  const errors = items.filter((i) => i.status === "error").length;
  const cancelled = items.filter((i) => i.status === "cancelled").length;
  const settled = done + errors + cancelled;

  // At most one file is active at a time (the loop awaits each), so .find() is
  // unambiguous. The active file is either mid-transfer ("uploading") or fully
  // sent and being finalized on the server ("finalizing"). Returns undefined
  // when the batch is fully settled, or while the loop is between files.
  const active = items.find(
    (i) => i.status === "uploading" || i.status === "finalizing",
  );
  const isFinalizing = active?.status === "finalizing";
  // A finalizing file has already sent 100% of its bytes, so it counts as a
  // full unit toward the batch bar (not a fraction).
  const activePercent = isFinalizing ? 100 : (active?.progress ?? 0);

  // Fractional batch percent. Counting the in-flight file's partial progress
  // (e.g. 50%) as 0.5 of a completed file makes the bar move continuously
  // rather than jumping at each file boundary. Use 0..1 fractions then * 100.
  // For a single-file batch this naturally collapses to activePercent.
  const fractionalSettled = settled + (active ? activePercent / 100 : 0);
  const batchPercent = total === 0 ? 0 : (fractionalSettled / total) * 100;

  const isSingle = total === 1;
  // The "X" only becomes a plain "close" (dismiss) for a SINGLE-file batch —
  // there's nothing left to summarize once its body is on the server. In a
  // multi-file batch other files are still queued; dismissing hides the shared
  // batch toast, and because the loop keeps running, every later toast update
  // (progress AND the final summary) would silently no-op — the user would
  // lose all visibility into the rest of the queue. So keep the X wired to the
  // batch-level cancel while other files remain, even during a finalize.
  const canDismiss = isFinalizing && isSingle;

  return (
    <Stack gap={6}>
      <Group justify="space-between" wrap="nowrap" gap="xs">
        <Text size="sm" fw={500}>
          Uploading {total} {total === 1 ? "file" : "files"}
        </Text>
        <Group gap="xs" wrap="nowrap">
          {!isSingle && (
            <Text size="sm" c="dimmed">
              {settled}/{total} {errors > 0 && `(${errors} failed)`}
            </Text>
          )}
          {/* While transferring, the "X" cancels (aborts). For a single-file
              batch that has reached finalizing, the body is already on the
              server so it becomes a plain "close" (dismiss) that hides the
              toast and lets the upload finish in the background. In a
              multi-file batch it stays wired to cancel (see canDismiss). */}
          {(canDismiss ? onDismiss : onCancel) && (
            <Tooltip
              label={canDismiss ? "Close — the upload finishes on the server" : "Cancel upload"}
              withArrow
            >
              <ActionIcon
                variant="subtle"
                color="gray"
                size="sm"
                onClick={canDismiss ? onDismiss : onCancel}
                aria-label={canDismiss ? "Close upload notification" : "Cancel upload"}
              >
                <X size={14} />
              </ActionIcon>
            </Tooltip>
          )}
        </Group>
      </Group>
      {/* Default (omitted) color resolves to the active theme's primaryColor,
          so the bar matches whatever palette is selected. Pre-6b this was
          hardcoded `color="amber"` which broke once amber was no longer the
          active palette — the bar lost its fill entirely. `yellow` for
          error state still works (built-in Mantine palette). */}
      <Progress
        value={batchPercent}
        color={errors > 0 ? "yellow" : undefined}
        // Animated stripes during the server-side finalize phase so a bar
        // parked at 100% reads as "still working", not "hung".
        animated={isFinalizing}
      />
      {active && !isSingle && (
        // For multi-file batches, show the active filename below the bar so
        // the user knows which file is in flight. During the finalize phase,
        // say so rather than just naming the file.
        <Text size="xs" c="dimmed" truncate>
          {isFinalizing ? `Finalizing ${active.name} on server…` : active.name}
        </Text>
      )}
      {active && isSingle && (
        // For single-file batches, the bar IS the file's progress (per the
        // formula above). Show the filename + byte percent while transferring;
        // once the body is fully sent and the server is streaming to S3, swap
        // to "Finalizing on server…" and drop the percent (it's parked at 100).
        <Group justify="space-between" wrap="nowrap" gap="xs">
          <Text size="xs" c="dimmed" truncate style={{ flex: 1, minWidth: 0 }}>
            {isFinalizing ? "Finalizing on server…" : active.name}
          </Text>
          {!isFinalizing && (
            <Text size="xs" c="dimmed">
              {Math.round(activePercent)}%
            </Text>
          )}
        </Group>
      )}
      {canDismiss && (
        // Reassure the user they don't have to sit and watch — the body is on
        // the server now, so it finishes even if they close this or leave.
        // Only for single-file batches: in a multi-file batch closing would
        // hide the queue's progress + summary, so we don't invite it there.
        <Text size="xs" c="dimmed">
          Safe to close — the upload will finish on the server.
        </Text>
      )}
    </Stack>
  );
}
