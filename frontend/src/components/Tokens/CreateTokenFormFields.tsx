import { Alert, Button, Group, NumberInput, Select, Stack, Switch, Text, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import type { CreateTokenPayload } from "@/types/api";

const HARD_CEILING = 10 * 1024 * 1024;

export interface CreateTokenFormFieldsProps {
  onClose: () => void;
  onSubmit: (payload: CreateTokenPayload, userId?: number) => void;
  loading: boolean;
  used: number;
  limit: number;
  /** Admin mode shows a user-picker so the admin can create tokens on
   * behalf of any user. Off → normal self-service flow. */
  adminMode?: boolean;
  availableUsers?: Array<{ id: number; username: string }>;
}

/**
 * Shared form for creating MCP tokens. Used by both `CreateTokenDrawer`
 * (standalone /admin/api-tokens + /me/api-tokens pages — Drawer matches
 * the BansPage/RolesPage/UsersPage edit pattern for visual consistency)
 * and `CreateTokenModal` (used inside the admin UserDrawer where a
 * stacked second drawer would conflict with focus + overlay handling).
 *
 * Owns the form state, validation, slot-limit gating, and MB→bytes
 * conversion on submit. Wrappers only provide chrome.
 */
export function CreateTokenFormFields({
  onClose,
  onSubmit,
  loading,
  used,
  limit,
  adminMode = false,
  availableUsers = [],
}: CreateTokenFormFieldsProps) {
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
        <Text size="sm" c="dimmed">
          MCP-only — for AI agents. Web API uses cookie auth.
        </Text>
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
        {!adminMode && (slotFull ? (
          <Alert color="red" title={`Token limit reached (${limit})`}>
            Revoke unused tokens before creating new ones.
          </Alert>
        ) : (
          <Text size="sm" c="dimmed">
            Used {used} of {limit} token slots.
          </Text>
        ))}
        <Group justify="flex-end" mt="sm">
          <Button variant="subtle" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button type="submit" loading={loading} disabled={!adminMode && slotFull}>
            Create
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
