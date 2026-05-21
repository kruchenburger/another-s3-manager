import { Progress, Stack, Text } from "@mantine/core";

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
}

export function BulkDeleteProgress({
  started,
  total,
  currentName,
}: BulkDeleteProgressProps) {
  // Show the 1-based position of the in-flight item so the headline reads
  // "Deleting 1 of 10" on the first iteration, not "Deleting 0 of 10".
  const position = Math.min(started + 1, total);
  const percent =
    total === 0 ? 0 : Math.min(100, Math.round((position / total) * 100));
  const headline = `Deleting ${position} of ${total}${currentName ? `: ${currentName}` : ""}`;
  return (
    <Stack gap={6}>
      <Text size="sm">{headline}</Text>
      <Progress value={percent} aria-label="Bulk delete progress" />
    </Stack>
  );
}
