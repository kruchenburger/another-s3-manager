import { useEffect, useRef } from "react";
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
  /**
   * Target token. May be null while the drawer is closing — keep the drawer
   * mounted and switch `opened` instead of unmounting on close, so Mantine
   * runs the slide-out animation. The component holds the last non-null
   * token internally so the form keeps its layout during the close.
   */
  token: ApiToken | null;
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
  // Hold on to the last non-null token so the form keeps rendering with valid
  // data while the drawer slides out (parent typically clears editTarget on
  // close, but Mantine's animation runs ~250ms after `opened` flips to false).
  const lastTokenRef = useRef<ApiToken | null>(token);
  if (token) lastTokenRef.current = token;
  const activeToken = token ?? lastTokenRef.current;

  const form = useForm<FormValues>({
    initialValues: activeToken
      ? {
          name: activeToken.name,
          is_read_only: activeToken.is_read_only,
          max_read_mb: bytesToMB(activeToken.max_read_bytes),
        }
      : { name: "", is_read_only: false, max_read_mb: 1 },
    validate: {
      name: (v) => (v.trim().length === 0 ? "Name is required" : null),
      max_read_mb: (v) => (v < 1 ? "Must be at least 1 MB" : null),
    },
  });

  // Re-prime form when the target token changes (e.g. user opens edit on a
  // different row without unmounting the drawer between renders). Skip when
  // token is null (close-animation in flight) so we don't blank the inputs
  // mid-slide.
  useEffect(() => {
    if (!token) return;
    const next = {
      name: token.name,
      is_read_only: token.is_read_only,
      max_read_mb: bytesToMB(token.max_read_bytes),
    };
    form.setInitialValues(next);
    form.setValues(next);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token?.id, token?.name, token?.is_read_only, token?.max_read_bytes]);

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
            <Button type="submit" loading={loading} disabled={loading}>
              Save
            </Button>
          </Group>
        </div>
      </form>
    </Drawer>
  );
}
