import {
  Autocomplete,
  Badge,
  Code,
  Group,
  Paper,
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
import { RoleTypePicker, OPTIONS as ROLE_TYPE_OPTIONS } from "./RoleTypePicker";

// Public AWS regions (commercial partition only — gov-cloud / cn aren't worth
// the extra entries; users can still type those in by hand because Autocomplete
// keeps the underlying TextInput free-form).
const AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "ca-west-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-central-2",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-south-1",
  "ap-south-2",
  "ap-east-1",
  "sa-east-1",
  "me-south-1",
  "me-central-1",
  "af-south-1",
  "il-central-1",
  // Commonly typed for S3-compatible services
  "auto",
];

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

/**
 * Compact reminder shown at the top of the wizard's credentials step so the
 * user doesn't have to remember which type they picked one screen ago.
 * Renders the same icon + friendly label + monospace code from the picker,
 * plus the one-liner description so they can recall the trade-off without
 * stepping back.
 */
function RoleTypeSummary({ type }: { type: AppRole["type"] }) {
  const opt = ROLE_TYPE_OPTIONS.find((o) => o.value === type);
  if (!opt) return null;
  return (
    <Paper p="sm" withBorder radius="md" bg="var(--mantine-color-default-hover)">
      <Group gap="xs" wrap="nowrap" mb={4}>
        {opt.icon}
        <Text fw={500}>{opt.label}</Text>
        <Code>{opt.value}</Code>
        <Badge size="xs" variant="light" color="gray">selected</Badge>
      </Group>
      <Text size="xs" c="dimmed">
        {opt.description}
      </Text>
    </Paper>
  );
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
          <TextInput
            label="Description"
            description="Optional human-friendly note shown in the admin UI."
            disabled={disabled}
            {...form.getInputProps("description")}
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
          {step === "credentials" && <RoleTypeSummary type={type} />}

          {type === "profile" && (
            <TextInput
              label="Profile name"
              required
              disabled={disabled}
              description="Name of a profile in ~/.aws/credentials or ~/.aws/config (incl. AWS SSO). The container needs that file mounted."
              placeholder="my-prod-profile"
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
              <Autocomplete
                label="Region"
                description={
                  type === "s3_compatible"
                    ? "Free-form for non-AWS services. Common values: 'auto' (R2), 'us-east-1' (MinIO)."
                    : "Pick from the list or type a custom value."
                }
                placeholder="us-east-1"
                disabled={disabled}
                data={AWS_REGIONS}
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
                description="How the bucket name is placed in the request URL — `virtual` puts it in the host (bucket.host), `path` puts it in the path (host/bucket). Most managed S3 services use virtual; self-hosted / on-prem services (MinIO, Ceph, SeaweedFS) usually need path. `auto` lets boto3 decide per-host."
                data={[
                  { value: "auto", label: "auto (let boto3 decide)" },
                  { value: "virtual", label: "virtual (bucket.host) — most managed S3" },
                  { value: "path", label: "path (host/bucket) — MinIO, Ceph, on-prem" },
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
        </>
      )}
    </Stack>
  );
}
