import {
  Alert,
  Button,
  Group,
  Paper,
  Stack,
  Tabs,
  Text,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { Download } from "lucide-react";
import { useEffect } from "react";
import {
  useAdminConfig,
  useSaveConfig,
} from "@/features/admin/hooks/useAdminConfig";
import { exportConfig } from "@/features/admin/api/adminApi";
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
 * Layout is split across three Mantine tabs (General / Security / MCP) so
 * editing each section stays focused. One shared useForm + one wrapping
 * <form> means clicking Save submits the whole config to POST /api/config
 * — which is atomic anyway, so splitting into per-tab POSTs would be a
 * fiction. Dirty state is shared across tabs: editing General then opening
 * Security and clicking Save persists both edits.
 *
 * The Save bar is sticky-pinned to the bottom of the page so it never
 * disappears below the fold no matter which tab the user is on or how
 * far down they've scrolled. It shows "You have unsaved changes" copy
 * when dirty so the user always knows their state.
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
    // Inline validation as the user types — so a value like 1500 in
    // "Items per page" lights up the input in red with a tooltip-style
    // helper underneath, instead of waiting until Save is clicked. Same
    // visual pattern (red border + descriptive text under the input)
    // works for any field added here later.
    validateInputOnChange: true,
    validate: {
      items_per_page: (value) => {
        if (value < 10) return "Minimum is 10";
        // Backend caps at 1000 (S3 list_objects_v2 protocol limit).
        if (value > 1000)
          return "Maximum is 1000 — S3 lists at most 1000 keys per request";
        return null;
      },
    },
  });

  useEffect(() => {
    if (!config) return;
    // Background refetch guard: useAdminConfig invalidates on save and may
    // also refetch on its own (the query has no staleTime: Infinity opt-out).
    // If the user has uncommitted edits, a refetch that fires while they're
    // typing would silently clobber their work via setValues(populated). The
    // dirty check bails out in that window — when the user clicks Save (or
    // Discard) we explicitly advance the baseline below, which clears
    // isDirty and lets the next refetch populate normally.
    if (form.isDirty()) return;
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
  const isDirty = form.isDirty();
  // Block Save while any field fails inline validation — otherwise the user
  // could submit a known-bad value (e.g. items_per_page=1500) and watch the
  // backend bounce it with a 400. Validating client-side first keeps the
  // error close to the offending input.
  const hasValidationErrors = Object.keys(form.errors).length > 0;

  // Download current config as JSON via the existing GET /api/config/export
  // endpoint. Kept outside the form (the button lives next to the page title,
  // not inside the <form> element) so the click does NOT trigger form submit.
  // Enabled regardless of readOnly mode — read-only blocks edits, not exports.
  const handleDownloadConfig = async () => {
    try {
      const blob = await exportConfig();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "config.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      notifications.show({
        color: "red",
        message: `Failed to download config: ${getErrorMessage(err)}`,
      });
    }
  };

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
    // On success, advance the form's "baseline" to the values that exist at
    // the moment the response comes back — NOT the closure-captured `values`
    // snapshot from submit time. If the user edited a field while the POST
    // was in flight, the in-flight closure would mark those newer edits as
    // "clean" and silently lose them on the next reload. form.getValues()
    // reads the live React state, so any concurrent edits stay dirty and
    // visible.
    //
    // Why we reset here even though useSaveConfig invalidates the query:
    // the populate effect bails out when form.isDirty() is true (background
    // refetch guard), so the refetch alone can't be relied on to advance
    // the baseline after a save. Explicit reset closes that gap.
    runWithToasts(save, next, "Settings saved", () => {
      const current = form.getValues();
      form.setInitialValues(current);
      form.resetDirty(current);
    });
  });

  const handleReset = () => {
    // Snap back to the last-saved baseline (whatever setInitialValues set
    // it to most recently — either initial server load or the previous save).
    form.reset();
  };

  return (
    <Stack gap="md" pb={readOnly ? 0 : 80}>
      <Group justify="space-between" align="center">
        <Title order={2}>Settings</Title>
        <Button
          variant="default"
          leftSection={<Download size={14} />}
          onClick={handleDownloadConfig}
        >
          Download config (JSON)
        </Button>
      </Group>

      {readOnly && (
        <Alert color="yellow">
          These settings are mounted read-only (e.g. Kubernetes ConfigMap).
          Edits are disabled — modify the source ConfigMap to change them.
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
            <SettingsGeneralTab form={form} readOnly={readOnly} />
          </Tabs.Panel>

          <Tabs.Panel value="security">
            <SettingsSecurityTab form={form} readOnly={readOnly} />
          </Tabs.Panel>

          <Tabs.Panel value="mcp">
            <SettingsMcpTab form={form} readOnly={readOnly} />
          </Tabs.Panel>
        </Tabs>

        {/* Sticky Save bar — visible across every tab, never moves with
            content scroll. Hidden entirely in read-only mode (no edits
            possible, no Save needed). Pinned to the bottom edge of the
            main content area: `left` uses Mantine's
            `--app-shell-navbar-width` CSS variable so the bar respects the
            sidebar width (260px expanded, 60px collapsed) and never slides
            under the navbar. */}
        {!readOnly && (
          <Paper
            shadow="md"
            p="sm"
            radius={0}
            withBorder
            style={{
              position: "fixed",
              left: "var(--app-shell-navbar-width, 0px)",
              right: 0,
              bottom: 0,
              zIndex: 100,
              borderLeft: 0,
              borderRight: 0,
              borderBottom: 0,
            }}
          >
            <Group justify="flex-end" gap="sm" px="md">
              {isDirty && (
                <Text size="sm" c="dimmed" mr="auto">
                  You have unsaved changes
                </Text>
              )}
              <Button
                variant="default"
                onClick={handleReset}
                disabled={!isDirty || save.isPending}
              >
                Discard
              </Button>
              <Button
                type="submit"
                loading={save.isPending}
                // Belt-and-braces: Mantine's `loading` prop hides the label
                // and shows a spinner, but in v8 it does not unconditionally
                // block clicks (the underlying button stays enabled unless
                // disabled is also set). Without this extra guard a rapid
                // double-click during the network round-trip fires two
                // POST /api/config calls — same bug pattern flagged on the
                // RoleDrawer Save button in PR #24.
                disabled={!isDirty || save.isPending || hasValidationErrors}
              >
                Save settings
              </Button>
            </Group>
          </Paper>
        )}
      </form>
    </Stack>
  );
}
