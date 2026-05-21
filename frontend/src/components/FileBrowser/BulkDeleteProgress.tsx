import { Progress, Stack, Text } from "@mantine/core";

export interface BulkDeleteProgressProps {
  /** How many items finished (successfully or with failure) so far. */
  completed: number;
  /** Total items in the bulk-delete batch. */
  total: number;
  /** Name of the item currently being deleted; null when the batch is finishing. */
  currentName: string | null;
}

export function BulkDeleteProgress({
  completed,
  total,
  currentName,
}: BulkDeleteProgressProps) {
  const percent =
    total === 0 ? 0 : Math.min(100, Math.round((completed / total) * 100));
  const headline =
    completed >= total
      ? `Deleting ${total} of ${total}…`
      : `Deleting ${completed} of ${total}${currentName ? `: ${currentName}` : ""}`;
  return (
    <Stack gap={6}>
      <Text size="sm">{headline}</Text>
      <Progress value={percent} aria-label="Bulk delete progress" />
    </Stack>
  );
}
