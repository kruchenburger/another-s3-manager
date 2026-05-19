import { ActionIcon, Group, Progress, Stack, Text, Tooltip } from "@mantine/core";
import { X } from "lucide-react";

export interface UploadProgressItem {
  name: string;
  status: "pending" | "uploading" | "done" | "error" | "cancelled";
  error?: string;
  /** 0..100 percent of THIS file's body uploaded. Only meaningful while
   *  status === "uploading". Defaults to 0 until the browser fires the first
   *  progress event. */
  progress?: number;
}

interface UploadProgressProps {
  items: UploadProgressItem[];
  /** When supplied, a small "X" button renders next to the progress bar and
   *  invokes this callback. The callback should abort the in-flight upload
   *  and stop the loop from starting the next file. Omit to hide the button
   *  (e.g. in the final-summary state where there's nothing to cancel). */
  onCancel?: () => void;
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
export function UploadProgress({ items, onCancel }: UploadProgressProps) {
  const total = items.length;
  const done = items.filter((i) => i.status === "done").length;
  const errors = items.filter((i) => i.status === "error").length;
  const cancelled = items.filter((i) => i.status === "cancelled").length;
  const settled = done + errors + cancelled;

  // At most one file uploads at a time (the loop awaits each), so .find() is
  // unambiguous. Returns undefined when the batch is fully settled, or while
  // the loop is between files (e.g. resolving onSuccess of file N before
  // starting N+1).
  const current = items.find((i) => i.status === "uploading");
  const currentPercent = current?.progress ?? 0;

  // Fractional batch percent. Counting the in-flight file's partial progress
  // (e.g. 50%) as 0.5 of a completed file makes the bar move continuously
  // rather than jumping at each file boundary. Use 0..1 fractions then * 100.
  // For a single-file batch this naturally collapses to currentPercent.
  const fractionalSettled = settled + (current ? currentPercent / 100 : 0);
  const batchPercent = total === 0 ? 0 : (fractionalSettled / total) * 100;

  const isSingle = total === 1;

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
          {onCancel && (
            <Tooltip label="Cancel upload" withArrow>
              <ActionIcon
                variant="subtle"
                color="gray"
                size="sm"
                onClick={onCancel}
                aria-label="Cancel upload"
              >
                <X size={14} />
              </ActionIcon>
            </Tooltip>
          )}
        </Group>
      </Group>
      <Progress value={batchPercent} color={errors > 0 ? "yellow" : "amber"} />
      {current && !isSingle && (
        // For multi-file batches, show the current filename below the bar so
        // the user knows which file is being uploaded. Skip for single-file
        // batches — the headline already says "Uploading 1 file" and adding
        // the filename would just be visual noise.
        <Text size="xs" c="dimmed" truncate>
          {current.name}
        </Text>
      )}
      {current && isSingle && (
        // For single-file batches, the bar IS the file's progress (per the
        // formula above), so we still want to show the filename + the byte
        // percent under it for the user to see *which* file and *how far*.
        <Group justify="space-between" wrap="nowrap" gap="xs">
          <Text size="xs" c="dimmed" truncate style={{ flex: 1, minWidth: 0 }}>
            {current.name}
          </Text>
          <Text size="xs" c="dimmed">
            {Math.round(currentPercent)}%
          </Text>
        </Group>
      )}
    </Stack>
  );
}
