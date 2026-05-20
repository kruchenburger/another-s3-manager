import { Alert, Stack, Tabs, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useEffect } from "react";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { AppConfig } from "@/types/api";
import { SettingsGeneralTab } from "./SettingsGeneralTab";
import { SettingsSecurityTab } from "./SettingsSecurityTab";
import { SettingsMcpTab } from "./SettingsMcpTab";

const MB = 1024 * 1024;

/** Shape of the Settings form values. Exported so each tab body can type its
 *  `form` prop precisely — keeps `getInputProps("foo")` type-safe across the
 *  split components. */
export interface SettingsFormValues {
  items_per_page: number;
  disable_deletion: boolean;
  enable_lazy_loading: boolean;
  max_file_size_mb: number;
  auto_inline_extensions: string[];
  password_min_length: number;
  password_min_uppercase: number;
  password_min_lowercase: number;
  password_min_digits: number;
  password_min_special: number;
  mcp_enabled: boolean;
  mcp_disable_writes: boolean;
  mcp_text_extensions: string[];
  mcp_global_max_read_bytes_mb: number;
}

/**
 * Admin Settings page.
 *
 * Layout is split across three Mantine tabs (General / Security / MCP) so the
 * Save button is visible on every tab without scrolling — the long unified
 * form was below the fold on most viewports.
 *
 * One shared useForm + one wrapping <form> means clicking Save in any tab
 * submits the whole config to POST /api/config — which is atomic anyway, so
 * splitting into per-tab POSTs would be a fiction. Dirty state is shared
 * across tabs: editing General then opening Security and clicking Save
 * persists both edits.
 */
export function SettingsPage() {
  const { data: config, isLoading, error } = useAdminConfig();
  const save = useSaveConfig();

  const form = useForm<SettingsFormValues>({
    initialValues: {
      items_per_page: 200,
      disable_deletion: false,
      enable_lazy_loading: true,
      max_file_size_mb: 100,
      auto_inline_extensions: [],
      password_min_length: 8,
      password_min_uppercase: 1,
      password_min_lowercase: 1,
      password_min_digits: 1,
      password_min_special: 0,
      mcp_enabled: true,
      mcp_disable_writes: false,
      mcp_text_extensions: [],
      mcp_global_max_read_bytes_mb: 10,
    },
  });

  useEffect(() => {
    if (!config) return;
    const populated: SettingsFormValues = {
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

  const onSubmit = form.onSubmit((values) => {
    const next: AppConfig = {
      ...toWritableConfig(config),
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
      // Same byte-precision preservation for the MCP read-cap MB field.
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
        {/* keepMounted: keeps inactive tab panels in the DOM so their inputs
            participate in the form, screen-readers can announce them, and
            React Testing Library can find them by label without a tab click.
            Field count is small (14 total), perf cost is negligible. */}
        <Tabs defaultValue="general" keepMounted>
          <Tabs.List>
            <Tabs.Tab value="general">General</Tabs.Tab>
            <Tabs.Tab value="security">Security</Tabs.Tab>
            <Tabs.Tab value="mcp">MCP</Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="general">
            <SettingsGeneralTab form={form} readOnly={readOnly} isPending={save.isPending} />
          </Tabs.Panel>

          <Tabs.Panel value="security">
            <SettingsSecurityTab form={form} readOnly={readOnly} isPending={save.isPending} />
          </Tabs.Panel>

          <Tabs.Panel value="mcp">
            <SettingsMcpTab form={form} readOnly={readOnly} isPending={save.isPending} />
          </Tabs.Panel>
        </Tabs>
      </form>
    </Stack>
  );
}
