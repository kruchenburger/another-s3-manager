import { useEffect } from "react";
import {
  Button,
  Drawer,
  Group,
  NumberInput,
  Stack,
  Switch,
  TextInput,
} from "@mantine/core";
import { useForm } from "@mantine/form";

import type { ApiToken, UpdateTokenPayload } from "@/types/api";

const HARD_CEILING_BYTES = 10 * 1024 * 1024;

interface TokenEditDrawerProps {
  opened: boolean;
  onClose: () => void;
  onSubmit: (payload: UpdateTokenPayload) => void;
  loading: boolean;
  token: ApiToken;
}

interface FormValues {
  name: string;
  is_read_only: boolean;
  max_read_mb: number;
}

function bytesToMB(bytes: number): number {
  return Math.max(1, Math.round(bytes / (1024 * 1024)));
}

export function TokenEditDrawer({
  opened,
  onClose,
  onSubmit,
  loading,
  token,
}: TokenEditDrawerProps) {
  const form = useForm<FormValues>({
    initialValues: {
      name: token.name,
      is_read_only: token.is_read_only,
      max_read_mb: bytesToMB(token.max_read_bytes),
    },
    validate: {
      name: (v) => (v.trim().length === 0 ? "Name is required" : null),
      max_read_mb: (v) => (v < 1 ? "Must be at least 1 MB" : null),
    },
  });

  // Re-prime form when the target token changes (e.g. user opens edit on a
  // different row without unmounting the drawer between renders).
  useEffect(() => {
    const next = {
      name: token.name,
      is_read_only: token.is_read_only,
      max_read_mb: bytesToMB(token.max_read_bytes),
    };
    form.setInitialValues(next);
    form.setValues(next);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token.id, token.name, token.is_read_only, token.max_read_bytes]);

  const handleSubmit = form.onSubmit((values) => {
    const bytes = Math.min(
      HARD_CEILING_BYTES,
      Math.round(values.max_read_mb * 1024 * 1024),
    );
    onSubmit({
      name: values.name.trim(),
      is_read_only: values.is_read_only,
      max_read_bytes: bytes,
    });
  });

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="md"
      title="Edit MCP token"
      // Make the drawer body a flex column so the form can stretch and the
      // sticky footer (Cancel / Save) stays pinned to the bottom regardless
      // of inner content height. `calc(100% - 60px)` accounts for the
      // Mantine Drawer header height.
      styles={{
        body: {
          display: "flex",
          flexDirection: "column",
          height: "calc(100% - 60px)",
          overflow: "hidden",
        },
      }}
    >
      <form
        onSubmit={handleSubmit}
        style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}
      >
        <Stack gap="md" style={{ flex: 1, overflowY: "auto", paddingRight: 4 }}>
          <TextInput label="Name" required {...form.getInputProps("name")} />
          <Switch
            label="Read-only"
            description="Token can list and read but not upload or delete."
            {...form.getInputProps("is_read_only", { type: "checkbox" })}
          />
          <NumberInput
            label="Max read (MB)"
            description="Per-call cap on read_file size. Hard server ceiling: 10 MB."
            min={1}
            max={10}
            step={1}
            {...form.getInputProps("max_read_mb")}
          />
        </Stack>
        <div
          style={{
            paddingTop: 12,
            marginTop: 12,
            borderTop: "1px solid var(--mantine-color-default-border)",
          }}
        >
          <Group justify="space-between">
            <Button variant="subtle" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            <Button type="submit" loading={loading}>
              Save
            </Button>
          </Group>
        </div>
      </form>
    </Drawer>
  );
}
