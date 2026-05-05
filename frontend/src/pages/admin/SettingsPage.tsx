import {
  Alert,
  Button,
  NumberInput,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useEffect } from "react";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { AppConfig } from "@/types/api";

const MB = 1024 * 1024;

export function SettingsPage() {
  const { data: config, isLoading, error } = useAdminConfig();
  const save = useSaveConfig();

  const form = useForm({
    initialValues: {
      default_role: "",
      items_per_page: 200,
      disable_deletion: false,
      enable_lazy_loading: true,
      max_file_size_mb: 100,
      auto_inline_extensions: [] as string[],
      password_min_length: 8,
      password_min_uppercase: 1,
      password_min_lowercase: 1,
      password_min_digits: 1,
      password_min_special: 0,
      // MCP server fields (MB-converted value stored separately)
      mcp_enabled: true,
      mcp_disable_writes: false,
      mcp_text_extensions: [] as string[],
      mcp_global_max_read_bytes_mb: 10,
    },
  });

  useEffect(() => {
    if (!config) return;
    const populated = {
      default_role: config.default_role ?? "",
      items_per_page: config.items_per_page,
      disable_deletion: config.disable_deletion,
      enable_lazy_loading: config.enable_lazy_loading,
      max_file_size_mb: Math.round(config.max_file_size / MB),
      auto_inline_extensions: config.auto_inline_extensions ?? [],
      password_min_length: config.password_min_length,
      password_min_uppercase: config.password_min_uppercase,
      password_min_lowercase: config.password_min_lowercase,
      password_min_digits: config.password_min_digits,
      password_min_special: config.password_min_special,
      mcp_enabled: config.mcp_enabled,
      mcp_disable_writes: config.mcp_disable_writes,
      mcp_text_extensions: config.mcp_text_extensions ?? [],
      // Convert bytes → MB for the NumberInput display
      mcp_global_max_read_bytes_mb: config.mcp_global_max_read_bytes / MB,
    };
    // setInitialValues so form.isDirty() correctly reports which fields the
    // user has actually modified (vs. fields populated from server data).
    form.setInitialValues(populated);
    form.setValues(populated);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config]);

  if (isLoading) return null;

  if (error) {
    return (
      <EmptyState
        tone="warning"
        title="Couldn't load settings"
        description={getErrorMessage(error)}
      />
    );
  }

  if (!config) return null;

  const readOnly = config.is_read_only === true;
  const roleOptions = config.roles.map((r) => ({ value: r.name, label: r.name }));

  const onSubmit = form.onSubmit((values) => {
    const next: AppConfig = {
      ...toWritableConfig(config),
      default_role: values.default_role || undefined,
      items_per_page: values.items_per_page,
      disable_deletion: values.disable_deletion,
      enable_lazy_loading: values.enable_lazy_loading,
      // Preserve original byte precision when the user didn't touch the MB field
      // (handles non-MiB-aligned values from k8s ConfigMaps).
      max_file_size: form.isDirty("max_file_size_mb")
        ? values.max_file_size_mb * MB
        : config.max_file_size,
      auto_inline_extensions: values.auto_inline_extensions,
      password_min_length: values.password_min_length,
      password_min_uppercase: values.password_min_uppercase,
      password_min_lowercase: values.password_min_lowercase,
      password_min_digits: values.password_min_digits,
      password_min_special: values.password_min_special,
      mcp_enabled: values.mcp_enabled,
      mcp_disable_writes: values.mcp_disable_writes,
      mcp_text_extensions: values.mcp_text_extensions,
      // Preserve original byte precision when user didn't touch the MB field
      mcp_global_max_read_bytes: form.isDirty("mcp_global_max_read_bytes_mb")
        ? Math.round(values.mcp_global_max_read_bytes_mb * MB)
        : config.mcp_global_max_read_bytes,
    };
    runWithToasts(save, next, "Settings saved");
  });

  return (
    <Stack gap="md">
      <Title order={2}>Settings</Title>

      {readOnly && (
        <Alert color="yellow">
          These settings are mounted read-only (e.g. Kubernetes ConfigMap). Edits
          are disabled — modify the source ConfigMap to change them.
        </Alert>
      )}

      <form onSubmit={onSubmit}>
        <Stack gap="md" maw={520}>
          <Select
            label="Default role"
            description="Role pre-selected for users who have access to it."
            data={roleOptions}
            disabled={readOnly}
            clearable
            {...form.getInputProps("default_role")}
          />
          <NumberInput
            label="Items per page"
            min={10}
            max={1000}
            step={10}
            disabled={readOnly}
            {...form.getInputProps("items_per_page")}
          />
          <Switch
            label="Disable deletion"
            description="When on, S3 file/folder delete operations return 403 server-side. Admin actions (deleting users, removing bans, deleting roles) are NOT affected."
            disabled={readOnly}
            {...form.getInputProps("disable_deletion", { type: "checkbox" })}
          />
          <Switch
            label="Enable lazy loading"
            description="Pagination on file lists for large buckets."
            disabled={readOnly}
            {...form.getInputProps("enable_lazy_loading", { type: "checkbox" })}
          />
          <NumberInput
            label="Max upload file size (MB)"
            min={1}
            max={5120}
            disabled={readOnly}
            {...form.getInputProps("max_file_size_mb")}
          />
          <TagsInput
            label="Auto-inline extensions"
            description="Files with these extensions render inline in the preview modal. e.g. txt, md, json"
            disabled={readOnly}
            {...form.getInputProps("auto_inline_extensions")}
          />
          <Title order={3} mt="md">
            Password policy
          </Title>
          <Text size="sm" c="dimmed">
            Enforced when a user changes their own password or an admin
            creates/resets another user&apos;s password. Set any value to 0 to
            disable that requirement. Existing passwords are not re-validated.
          </Text>
          <NumberInput
            label="Minimum length"
            description="Set to 0 to disable"
            min={0}
            max={50}
            step={1}
            disabled={readOnly}
            {...form.getInputProps("password_min_length")}
          />
          <NumberInput
            label="Minimum uppercase letters"
            description="Set to 0 to disable"
            min={0}
            max={50}
            step={1}
            disabled={readOnly}
            {...form.getInputProps("password_min_uppercase")}
          />
          <NumberInput
            label="Minimum lowercase letters"
            description="Set to 0 to disable"
            min={0}
            max={50}
            step={1}
            disabled={readOnly}
            {...form.getInputProps("password_min_lowercase")}
          />
          <NumberInput
            label="Minimum digits"
            description="Set to 0 to disable"
            min={0}
            max={50}
            step={1}
            disabled={readOnly}
            {...form.getInputProps("password_min_digits")}
          />
          <NumberInput
            label="Minimum special characters"
            description="Set to 0 to disable"
            min={0}
            max={50}
            step={1}
            disabled={readOnly}
            {...form.getInputProps("password_min_special")}
          />
          <Title order={3} mt="md">
            MCP Server
          </Title>
          <Text size="sm" c="dimmed">
            Model Context Protocol server for AI agents. Changes take effect
            immediately after save. Token-level caps still apply on top of these
            global limits.
          </Text>
          <Switch
            label="Enable MCP server"
            description="When off, /mcp/* endpoints return 503."
            disabled={readOnly}
            {...form.getInputProps("mcp_enabled", { type: "checkbox" })}
          />
          <Switch
            label="Disable writes via MCP"
            description="Forces all MCP tokens to read-only regardless of their per-token flag."
            disabled={readOnly}
            {...form.getInputProps("mcp_disable_writes", { type: "checkbox" })}
          />
          <NumberInput
            label="Global max read bytes (MB)"
            description="Server-wide cap on read_file response size. Applied as min(token cap, this). Hard ceiling: 10 MB."
            min={0.001}
            max={10}
            step={0.5}
            decimalScale={3}
            disabled={readOnly}
            {...form.getInputProps("mcp_global_max_read_bytes_mb")}
          />
          <TagsInput
            label="Additional text extensions for read_file"
            description="Per-deployment whitelist extensions beyond built-in defaults (e.g. mdx, rst, adoc)."
            placeholder="Add extension and press Enter"
            disabled={readOnly}
            {...form.getInputProps("mcp_text_extensions")}
          />
          {!readOnly && (
            <Button type="submit" loading={save.isPending}>
              Save settings
            </Button>
          )}
        </Stack>
      </form>
    </Stack>
  );
}
