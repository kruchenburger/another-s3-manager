import {
  Anchor,
  PasswordInput,
  Radio,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { AppRole } from "@/types/api";

interface Props {
  form: UseFormReturnType<AppRole>;
  disabled?: boolean;
  mode: "create" | "edit";
  /**
   * True for the wizard's Step 2 (Credentials) — hides name + type Radio because
   * the wizard's Step 1 already set them. Type-conditional fields AND universal
   * `allowed_buckets` + `description` STILL render here. The wizard intentionally
   * collapses "credentials" and "scope" into one step to avoid 4-step UX where
   * default/profile/assume_role types would have an empty Step 3.
   */
  hideNameAndType?: boolean;
}

const TYPE_DESCRIPTIONS: Record<AppRole["type"], React.ReactNode> = {
  default: (
    <>
      Uses the default AWS credential chain (env vars, IAM role, ~/.aws/config) — no
      credentials needed in the manager. Pick this when running on EC2/ECS/EKS with
      an instance role.{" "}
      <Anchor
        href="https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html"
        target="_blank"
        rel="noopener noreferrer"
      >
        Learn more
      </Anchor>
    </>
  ),
  profile: (
    <>
      Use a named profile from <code>~/.aws/credentials</code> or AWS SSO config.
    </>
  ),
  assume_role: (
    <>
      Assume an IAM role via STS. The container needs base credentials with
      sts:AssumeRole permission for the target role.
    </>
  ),
  credentials: (
    <>
      Use static AWS access key + secret. Simplest option but credentials live in
      this app&apos;s config — prefer Default or Assume Role when possible.
    </>
  ),
  s3_compatible: (
    <>
      Use any S3-compatible service: MinIO, Cloudflare R2, Backblaze B2, Wasabi,
      etc. Requires an explicit endpoint URL.
    </>
  ),
};

export function RoleFormFields({ form, disabled, mode, hideNameAndType }: Props) {
  const type = form.values.type;
  return (
    <Stack gap="md">
      {!hideNameAndType && (
        <>
          <TextInput
            label="Name"
            required
            disabled={disabled || mode === "edit"}
            description={mode === "edit" ? "Cannot be changed after creation." : undefined}
            {...form.getInputProps("name")}
          />
          <Radio.Group label="Type" required {...form.getInputProps("type")}>
            <Stack gap="xs" mt="xs">
              {(["default", "profile", "assume_role", "credentials", "s3_compatible"] as const).map((t) => (
                <Radio
                  key={t}
                  value={t}
                  disabled={disabled}
                  label={
                    <Stack gap={2}>
                      <Text fw={500}>{t}</Text>
                      <Text size="xs" c="dimmed">{TYPE_DESCRIPTIONS[t]}</Text>
                    </Stack>
                  }
                />
              ))}
            </Stack>
          </Radio.Group>
        </>
      )}

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
    </Stack>
  );
}
