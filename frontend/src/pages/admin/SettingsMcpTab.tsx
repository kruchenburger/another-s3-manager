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
      <NumberInput
        label={
          <FieldLabelWithHelp
            label="Summary scan cap"
            help="Maximum keys the bucket_summary walk may visit per call (~50 S3 list requests per 50000 keys). When a bucket is larger, the response is marked incomplete with per-prefix coverage — numbers are never guessed."
          />
        }
        description="Default 50000 keys."
        min={1000}
        max={1000000}
        step={1000}
        disabled={readOnly}
        {...form.getInputProps("mcp_summary_max_keys")}
      />
      <NumberInput
        label={
          <FieldLabelWithHelp
            label="Summary prefix-scan pages"
            help="How far bucket_summary will page just to enumerate the prefixes at a level. Raise it only for buckets with many loose objects sitting directly at the scanned level."
          />
        }
        description="Default 20 pages (1000 entries each)."
        min={1}
        max={200}
        step={5}
        disabled={readOnly}
        {...form.getInputProps("mcp_summary_prefix_scan_pages")}
      />
      <NumberInput
        label={
          <FieldLabelWithHelp
            label="Default list page size"
            help="Page size for the list_files MCP tool when the agent does not pass max_keys. If the max list page size below is set lower, the ceiling wins."
          />
        }
        description="Default 1000 keys."
        min={1}
        max={10000}
        step={100}
        disabled={readOnly}
        {...form.getInputProps("mcp_list_page_size")}
      />
      <NumberInput
        label={
          <FieldLabelWithHelp
            label="Max list page size"
            help="Hard ceiling on the max_keys an agent may request from list_files. Requests above it are clamped, not rejected. 10000 matches the previous built-in ceiling; going above it is not useful."
          />
        }
        description="Default 10000 keys."
        min={1}
        max={10000}
        step={1000}
        disabled={readOnly}
        {...form.getInputProps("mcp_list_max_page_size")}
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
