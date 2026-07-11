import { NumberInput, Select, Stack, Switch, TagsInput, Text } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import { FieldLabelWithHelp } from "@/components/FieldLabelWithHelp/FieldLabelWithHelp";
import { ttlSelectDataUpTo, withConfiguredValue } from "@/utils/ttlPresets";
import type { SettingsFormValues } from "./SettingsPage";

interface SettingsGeneralTabProps {
  form: UseFormReturnType<SettingsFormValues>;
  readOnly: boolean;
}

export function SettingsGeneralTab({ form, readOnly }: SettingsGeneralTabProps) {
  return (
    <Stack gap="md" maw={520} mt="md">
      <NumberInput
        label={
          <FieldLabelWithHelp
            label="Max client load"
            help="Objects loaded into the browser before 'Load more' appears. Larger folders paginate on the server beyond this. Default 10000."
          />
        }
        description="Default 10000."
        min={1}
        max={200000}
        step={1000}
        disabled={readOnly}
        {...form.getInputProps("max_client_load")}
      />
      <Switch
        label={
          <FieldLabelWithHelp
            label="Disable deletion"
            help="When on, S3 file/folder delete operations return 403 server-side. Admin actions (deleting users, removing bans, deleting roles) are NOT affected."
          />
        }
        description="Blocks S3 file/folder deletes; admin actions unaffected."
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
        label={
          <FieldLabelWithHelp
            label="Inline preview extensions (text)"
            help="Text files with these extensions preview inline in the UI. Pre-filled with sensible text defaults — add, remove, or clear them all to disable text preview entirely. Images, video and PDF always preview regardless."
          />
        }
        description="Pre-filled with sensible text defaults."
        disabled={readOnly}
        {...form.getInputProps("preview_text_extensions")}
      />
      <TagsInput
        label={
          <FieldLabelWithHelp
            label="Open in browser on upload"
            help="Files with these extensions get Content-Disposition: inline set when uploaded, so they open in the browser (instead of downloading) when served via a CDN or presigned link. Applies to new uploads only. Defaults to pdf + common images."
          />
        }
        description="Defaults to pdf + common images."
        disabled={readOnly}
        {...form.getInputProps("upload_inline_extensions")}
      />
      <Text fw={600} size="sm" mt="sm">
        Presigned URLs
      </Text>
      <Select
        label="Default link validity"
        description="Lifetime applied when a user copies a link without choosing one."
        data={withConfiguredValue(
          ttlSelectDataUpTo(form.values.presigned_url_max_ttl),
          form.values.presigned_url_default_ttl,
        )}
        value={String(form.values.presigned_url_default_ttl)}
        onChange={(v) => v && form.setFieldValue("presigned_url_default_ttl", Number(v))}
        error={form.errors.presigned_url_default_ttl}
        allowDeselect={false}
        disabled={readOnly}
      />
      <Select
        label={
          <FieldLabelWithHelp
            label="Maximum link validity"
            help="Upper bound for per-link overrides. Ceiling is 7 days (AWS SigV4). Roles using temporary credentials (assume_role / profile) may expire sooner regardless."
          />
        }
        description="Ceiling: 7 days (AWS SigV4 limit)."
        data={withConfiguredValue(ttlSelectDataUpTo(604800), form.values.presigned_url_max_ttl)}
        value={String(form.values.presigned_url_max_ttl)}
        onChange={(v) => {
          if (!v) return;
          form.setFieldValue("presigned_url_max_ttl", Number(v));
          form.validateField("presigned_url_default_ttl");
        }}
        error={form.errors.presigned_url_max_ttl}
        allowDeselect={false}
        disabled={readOnly}
      />
    </Stack>
  );
}
