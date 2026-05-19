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
 * Two-level progress for a batched upload:
 *
 *   - the outer bar is the BATCH progress (N of M files done) — same as before
 *   - the inner Text shows the CURRENT file's name + its own byte-level
 *     percentage, so a single large file no longer looks like a frozen toast
 *     at "0/1" for minutes
 *
 * The cancel button is rendered next to the headline so it's easy to find
 * during a long batch; clicking it aborts the in-flight XHR via the consumer's
 * AbortController and stops subsequent files in the loop from starting.
 */
export function UploadProgress({ items, onCancel }: UploadProgressProps) {
  const total = items.length;
  const done = items.filter((i) => i.status === "done").length;
  const errors = items.filter((i) => i.status === "error").length;
  const cancelled = items.filter((i) => i.status === "cancelled").length;
  const settled = done + errors + cancelled;
  const batchPercent = total === 0 ? 0 : Math.round((settled / total) * 100);

  // The currently-uploading file (at most one at a time — uploads run
  // sequentially). Use this to surface byte-level progress for big files.
  const current = items.find((i) => i.status === "uploading");
  const currentPercent = current?.progress ?? 0;

  return (
    <Stack gap={6}>
      <Group justify="space-between" wrap="nowrap" gap="xs">
        <Text size="sm" fw={500}>
          Uploading {total} {total === 1 ? "file" : "files"}
        </Text>
        <Group gap="xs" wrap="nowrap">
          <Text size="sm" c="dimmed">
            {settled}/{total} {errors > 0 && `(${errors} failed)`}
          </Text>
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
      {current && (
        <Group justify="space-between" wrap="nowrap" gap="xs">
          <Text size="xs" c="dimmed" truncate style={{ flex: 1, minWidth: 0 }}>
            {current.name}
          </Text>
          <Text size="xs" c="dimmed">
            {currentPercent}%
          </Text>
        </Group>
      )}
    </Stack>
  );
}
