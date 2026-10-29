import { Alert, Button, Group, Modal, Stack, Text } from "@mantine/core";
import type { MovePreflight } from "@/types/api";
import {
  LARGE_MOVE_WARNING,
  moveExplanation,
} from "@/features/files/utils/folderOperations";
interface Props {
  preflight: MovePreflight;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
  disabled?: boolean;
  error?: string | null;
}
export function ConfirmMoveModal({
  preflight,
  onConfirm,
  onClose,
  busy,
  disabled,
  error,
}: Props) {
  return (
    <Modal
      opened
      onClose={onClose}
      title="Confirm move"
      closeButtonProps={{ "aria-label": "Close" }}
    >
      <Stack>
        <Text>{moveExplanation(preflight.objects, preflight.bytes)}</Text>
        {(preflight.objects > 100 || preflight.bytes > 1_000_000_000) && (
          <Text>{LARGE_MOVE_WARNING}</Text>
        )}
        {preflight.blocked_reason && (
          <Alert color="red">{preflight.blocked_reason}</Alert>
        )}
        {preflight.conflicts.map((failure, index) => (
          <Alert color="red" key={index}>
            {failure.code}: {failure.message} {failure.key}
          </Alert>
        ))}
        {error && (
          <Alert color="red" role="alert">
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            loading={busy}
            disabled={
              disabled ||
              !!preflight.blocked_reason ||
              preflight.conflicts.length > 0
            }
            onClick={onConfirm}
          >
            Start move
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
