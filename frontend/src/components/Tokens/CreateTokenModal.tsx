import {
  Alert,
  Button,
  Group,
  Modal,
  NumberInput,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import type { CreateTokenPayload } from "@/types/api";

interface CreateTokenModalProps {
  opened: boolean;
  onClose: () => void;
  onSubmit: (payload: CreateTokenPayload, userId?: number) => void;
  loading: boolean;
  used: number;
  limit: number;
  // Admin mode: shows user picker
  adminMode?: boolean;
  availableUsers?: Array<{ id: number; username: string }>;
}

const HARD_CEILING = 10 * 1024 * 1024;

export function CreateTokenModal({
  opened,
  onClose,
  onSubmit,
  loading,
  used,
  limit,
  adminMode = false,
  availableUsers = [],
}: CreateTokenModalProps) {
  const form = useForm<{ name: string; is_read_only: boolean; max_read_mb: number; user_id: string | null }>({
    initialValues: { name: "", is_read_only: true, max_read_mb: 1, user_id: null },
    validate: {
      name: (v) => (v.trim().length === 0 ? "Name is required" : null),
      max_read_mb: (v) =>
        v < 1 / 1024 || v > 10 ? "Must be between 1 KB (~0.001 MB) and 10 MB" : null,
      user_id: (v) => (adminMode && !v ? "Pick a user" : null),
    },
  });

  const slotFull = used >= limit;

  return (
    <Modal opened={opened} onClose={onClose} title="Create API token" centered size="md" radius="lg">
      <form
        onSubmit={form.onSubmit((vals) => {
          const max_read_bytes = Math.min(HARD_CEILING, Math.round(vals.max_read_mb * 1024 * 1024));
          onSubmit(
            { name: vals.name.trim(), is_read_only: vals.is_read_only, max_read_bytes },
            adminMode && vals.user_id ? Number(vals.user_id) : undefined,
          );
        })}
      >
        <Stack gap="md">
          {adminMode && (
            <Select
              label="User"
              placeholder="Pick the user this token will act on behalf of"
              required
              searchable
              data={availableUsers.map((u) => ({ value: String(u.id), label: u.username }))}
              {...form.getInputProps("user_id")}
            />
          )}
          <TextInput
            label="Name"
            placeholder="e.g. Claude Desktop"
            required
            {...form.getInputProps("name")}
          />
          <Switch
            label="Read-only"
            description="Token can list and read but not upload or delete."
            {...form.getInputProps("is_read_only", { type: "checkbox" })}
          />
          <NumberInput
            label="Max read bytes (MB)"
            description="Per-call cap on read_file size. Hard server ceiling: 10 MB."
            min={1 / 1024}
            max={10}
            step={0.5}
            decimalScale={3}
            {...form.getInputProps("max_read_mb")}
          />
          {slotFull ? (
            <Alert color="red" title={`Token limit reached (${limit})`}>
              Revoke unused tokens before creating new ones.
            </Alert>
          ) : (
            <Text size="sm" c="dimmed">
              Used {used} of {limit} token slots.
            </Text>
          )}
          <Group justify="flex-end" mt="sm">
            <Button variant="subtle" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" loading={loading} disabled={slotFull}>
              Create
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
