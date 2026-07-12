import { Button, Group, Modal, Stack, Text } from "@mantine/core";
import type { SortColumn } from "@/utils/sortEntries";

interface SortLoadAllModalProps {
  opened: boolean;
  /** The column the user asked to sort by — drives the copy. Null while closed. */
  column: SortColumn | null;
  /** How many objects are loaded so far (the level has more). */
  loadedCount: number;
  onCancel: () => void;
  onConfirm: () => void;
}

// Column label as it reads in a sentence ("sort by size?", "sort by modified date?").
const COLUMN_LABELS: Record<SortColumn, string> = {
  name: "name",
  size: "size",
  modified: "modified date",
};

// Per-column explanation of why sorting a partial load would lie to the user.
const MISLEADING_COPY: Record<SortColumn, string> = {
  size: "Sorting by size across just that part would mislead you: the biggest file you can see might not be the biggest one in the folder.",
  modified:
    "Sorting by date across just that part would mislead you: the newest file you can see might not be the newest one in the folder.",
  name: "Sorting this way across just that part would mislead you: the order would only reflect what happens to be loaded.",
};

/**
 * Confirmation gate shown before FileBrowser drains a truncated level to
 * apply a size/date/name sort. A header click alone must never kick off a
 * drain that can be thousands of S3 LIST requests on a huge folder — this
 * modal is the explicit opt-in the user gets first.
 *
 * `column` is null only while the modal is closed (the parent clears
 * `pendingSort` on cancel/confirm); falling back to "name" keeps the copy
 * well-typed for that brief unmounting window instead of throwing.
 */
export function SortLoadAllModal({
  opened,
  column,
  loadedCount,
  onCancel,
  onConfirm,
}: SortLoadAllModalProps) {
  const activeColumn = column ?? "name";

  return (
    <Modal
      opened={opened}
      onClose={onCancel}
      title={`Load the whole folder to sort by ${COLUMN_LABELS[activeColumn]}?`}
      centered
      size="md"
      radius="lg"
    >
      <Stack gap="md">
        <Text>
          Only part of this folder is loaded — {loadedCount}+ objects so far.{" "}
          {MISLEADING_COPY[activeColumn]}
        </Text>
        <Text c="dimmed" size="sm">
          Loading everything can take a while on very large folders. You can
          stop it at any time — the current order stays.
        </Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button onClick={onConfirm}>Load all and sort</Button>
        </Group>
      </Stack>
    </Modal>
  );
}
