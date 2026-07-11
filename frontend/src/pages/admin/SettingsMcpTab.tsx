import { NumberInput, Stack, Switch, TagsInput, Text } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import { FieldLabelWithHelp } from "@/components/FieldLabelWithHelp/FieldLabelWithHelp";
import type { SettingsFormValues } from "./SettingsPage";

interface SettingsMcpTabProps {
  form: UseFormReturnType<SettingsFormValues>;
  readOnly: boolean;
}

export function SettingsMcpTab({ form, readOnly }: SettingsMcpTabProps) {
  return (
    <Stack gap="md" maw={520} mt="md">
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
        label={
          <FieldLabelWithHelp
            label="Global max read bytes (MB)"
            help="Server-wide cap on read_file response size. Applied as min(token cap, this). Hard ceiling: 10 MB."
          />
        }
        description="Hard ceiling: 10 MB."
        min={0.001}
        max={10}
        step={0.5}
        decimalScale={3}
        disabled={readOnly}
        {...form.getInputProps("mcp_global_max_read_bytes_mb")}
      />
      <TagsInput
        label={
          <FieldLabelWithHelp
            label="Additional text extensions for read_file"
            help="Per-deployment whitelist extensions beyond built-in defaults (e.g. mdx, rst, adoc)."
          />
        }
        description="e.g. mdx, rst, adoc"
        placeholder="Add extension and press Enter"
        disabled={readOnly}
        {...form.getInputProps("mcp_text_extensions")}
      />
    </Stack>
  );
}
