import { Button, Group, List, Modal, Stack, Text } from "@mantine/core";

interface ConfirmDeleteModalProps {
  opened: boolean;
  onClose: () => void;
  onConfirm: () => void;
  /** Names of items to delete. If 1, shown inline. If many, shown as list. */
  items: string[];
  loading?: boolean;
}

export function ConfirmDeleteModal({
  opened,
  onClose,
  onConfirm,
  items,
  loading,
}: ConfirmDeleteModalProps) {
  const single = items.length === 1;

  return (
    <Modal opened={opened} onClose={onClose} title="Confirm deletion" centered>
      <Stack gap="md">
        {single ? (
          <Text>
            Delete <Text span fw={600}>{items[0]}</Text>? This cannot be undone.
          </Text>
        ) : (
          <>
            <Text>Delete the following {items.length} items? This cannot be undone.</Text>
            <List spacing={4} size="sm" withPadding>
              {items.slice(0, 10).map((name) => (
                <List.Item key={name}>{name}</List.Item>
              ))}
              {items.length > 10 && (
                <List.Item>
                  <Text c="dimmed">…and {items.length - 10} more</Text>
                </List.Item>
              )}
            </List>
          </>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button color="red" onClick={onConfirm} loading={loading}>
            Delete
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
