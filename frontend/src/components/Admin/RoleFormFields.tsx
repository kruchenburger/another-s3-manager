import {
  PasswordInput,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { AppRole } from "@/types/api";
import { RoleTypePicker } from "./RoleTypePicker";

interface Props {
  form: UseFormReturnType<AppRole>;
  disabled?: boolean;
  mode: "create" | "edit";
  /**
   * Controls which subset of fields renders.
   * - "type"        → name + RoleTypePicker only (wizard step 1)
   * - "credentials" → type-specific credential fields + allowed buckets + description (wizard step 2)
   * - "all"         → everything (single-page edit form)
   */
  step: "type" | "credentials" | "all";
}

export function RoleFormFields({ form, disabled, mode, step }: Props) {
  const type = form.values.type;
  const showType = step === "type" || step === "all";
  const showCredentials = step === "credentials" || step === "all";
  // Type changes break credential schema; not supported in edit mode.
  const typePickerDisabled = disabled || mode === "edit";

  return (
    <Stack gap="md">
      {showType && (
        <>
          <TextInput
            label="Name"
            required
            disabled={disabled || mode === "edit"}
            description={mode === "edit" ? "Cannot be changed after creation." : undefined}
            {...form.getInputProps("name")}
          />
          <div>
            <Text size="sm" fw={500} mb={4}>
              Type <span style={{ color: "var(--mantine-color-red-6)" }}>*</span>
            </Text>
            <RoleTypePicker
              value={type}
              onChange={(next) => form.setFieldValue("type", next)}
              disabled={typePickerDisabled}
            />
          </div>
        </>
      )}

      {showCredentials && (
        <>
          {type === "profile" && (
            <TextInput
              label="Profile name"
              required
              disabled={disabled}
              {...form.getInputProps("profile_name")}
            />
          )}

          {type === "assume_role" && (
            <TextInput
              label="Role ARN"
              placeholder="arn:aws:iam::123456789012:role/MyRole"
              required
              disabled={disabled}
              {...form.getInputProps("role_arn")}
            />
          )}

          {(type === "credentials" || type === "s3_compatible") && (
            <>
              <TextInput
                label="Access key ID"
                required
                disabled={disabled}
                {...form.getInputProps("access_key_id")}
              />
              <PasswordInput
                label="Secret access key"
                placeholder={mode === "edit" ? "Leave empty to keep existing secret" : undefined}
                required={mode === "create"}
                disabled={disabled}
                {...form.getInputProps("secret_access_key")}
              />
              <TextInput
                label="Region"
                description={
                  type === "s3_compatible"
                    ? "MinIO usually wants us-east-1; R2 wants auto."
                    : undefined
                }
                disabled={disabled}
                {...form.getInputProps("region")}
              />
            </>
          )}

          {type === "s3_compatible" && (
            <>
              <TextInput
                label="Endpoint URL"
                placeholder="https://<account>.r2.cloudflarestorage.com"
                required
                disabled={disabled}
                {...form.getInputProps("endpoint_url")}
              />
              <Switch
                label="Use SSL"
                disabled={disabled}
                {...form.getInputProps("use_ssl", { type: "checkbox" })}
              />
              <Switch
                label="Verify SSL"
                disabled={disabled}
                {...form.getInputProps("verify_ssl", { type: "checkbox" })}
              />
              <Select
                label="Addressing style"
                description="virtual = AWS/R2 default, path = MinIO. Auto picks per host."
                data={[
                  { value: "auto", label: "auto (default)" },
                  { value: "virtual", label: "virtual (AWS, R2)" },
                  { value: "path", label: "path (MinIO)" },
                ]}
                disabled={disabled}
                {...form.getInputProps("addressing_style")}
              />
            </>
          )}

          <TagsInput
            label="Allowed buckets"
            description="Required for R2 and other scoped tokens that cannot list all buckets. Leave empty only if your credentials have permission to list every bucket in the account."
            disabled={disabled}
            {...form.getInputProps("allowed_buckets")}
          />
          <TextInput
            label="Description"
            disabled={disabled}
            {...form.getInputProps("description")}
          />
        </>
      )}
    </Stack>
  );
}
