import { NumberInput, Stack, Switch, TagsInput } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { SettingsFormValues } from "./SettingsPage";

interface SettingsGeneralTabProps {
  form: UseFormReturnType<SettingsFormValues>;
  readOnly: boolean;
}

export function SettingsGeneralTab({ form, readOnly }: SettingsGeneralTabProps) {
  return (
    <Stack gap="md" maw={520} mt="md">
      <NumberInput
        label="Items per page"
        min={10}
        max={1000}
        step={10}
        disabled={readOnly}
        {...form.getInputProps("items_per_page")}
      />
      <NumberInput
        label="Max client load"
        description="Objects loaded into the browser before 'Load more' appears. Larger folders paginate on the server beyond this. Default 10000."
        min={1}
        max={200000}
        step={1000}
        disabled={readOnly}
        {...form.getInputProps("max_client_load")}
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
        label="Inline preview extensions"
        description="Files with these extensions preview inline. Pre-filled with sensible text defaults — add, remove, or clear them all to disable text preview entirely. Images, video and PDF always preview regardless."
        disabled={readOnly}
        {...form.getInputProps("auto_inline_extensions")}
      />
    </Stack>
  );
}
