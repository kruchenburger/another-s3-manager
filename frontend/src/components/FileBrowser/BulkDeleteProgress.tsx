import {
  ActionIcon,
  Group,
  Progress,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import { X } from "lucide-react";

export interface BulkDeleteProgressProps {
  /**
   * Index of the item currently being deleted (0-based). The UI tracks
   * the in-flight item, not finished ones — so on the first iteration
   * `started=0` renders "Deleting 1 of N: <name>" while item 0 is
   * actually being awaited.
   */
  started: number;
  /** Total items in the bulk-delete batch. */
  total: number;
  /** Name of the item currently being deleted. */
  currentName: string | null;
  /**
   * Called when the user clicks the Cancel button. The parent flips a
   * ref the in-flight loop checks before the next `deleteFile` call,
   * stopping the batch at the next iteration boundary. Already-issued
   * deletes can't be undone — S3 has no soft-delete unless versioning
   * is on.
   */
  onCancel?: () => void;
}

export function BulkDeleteProgress({
  started,
  total,
  currentName,
  onCancel,
}: BulkDeleteProgressProps) {
  // Show the 1-based position of the in-flight item so the headline reads
  // "Deleting 1 of 10" on the first iteration, not "Deleting 0 of 10".
  const position = Math.min(started + 1, total);
  const percent =
    total === 0 ? 0 : Math.min(100, Math.round((position / total) * 100));
  return (
    <Stack gap={6}>
      <Group justify="space-between" wrap="nowrap" gap="sm">
        <Text size="sm" fw={500}>
          Deleting {position} of {total}
        </Text>
        {onCancel && (
          <Tooltip label="Cancel bulk delete" position="top">
            <ActionIcon
              size="sm"
              variant="subtle"
              color="gray"
              onClick={onCancel}
              aria-label="Cancel bulk delete"
            >
              <X size={14} />
            </ActionIcon>
          </Tooltip>
        )}
      </Group>
      {currentName && (
        // `truncate` ellipsises long S3 keys instead of pushing the
        // notification width around.
        <Text size="xs" c="dimmed" truncate>
          {currentName}
        </Text>
      )}
      <Progress value={percent} aria-label="Bulk delete progress" />
    </Stack>
  );
}
