import { Button, Group, JsonInput, Stack, Stepper, Title } from "@mantine/core";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "@mantine/form";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { stripIrrelevantFields } from "@/features/admin/api/roleShape";
import { RoleFormFields } from "@/components/Admin/RoleFormFields";
import { runWithToasts } from "@/utils/mutationToast";
import { notifications } from "@mantine/notifications";
import type { AppConfig, AppRole } from "@/types/api";

const REDACTED = "***REDACTED***";

export function RoleNewPage() {
  const navigate = useNavigate();
  const { data: config } = useAdminConfig();
  const save = useSaveConfig();
  const [active, setActive] = useState(0);

  const form = useForm<AppRole>({
    initialValues: {
      name: "",
      type: "default",
      use_ssl: true,
      verify_ssl: true,
      addressing_style: "auto",
      allowed_buckets: [],
      secret_access_key: "",  // avoid PasswordInput controlled→uncontrolled warning when user starts typing
    } as AppRole,
    validate: {
      name: (v) => (!v || v.trim().length === 0 ? "Required" : null),
      profile_name: (v, values) =>
        values.type === "profile" && (!v || v.trim().length === 0)
          ? "Required for profile type"
          : null,
      role_arn: (v, values) => {
        if (values.type !== "assume_role") return null;
        if (!v || v.trim().length === 0) return "Required for assume_role type";
        // IAM Role ARN: arn:aws:iam::<12-digit-account>:role/<RoleName>
        // Allows aws-cn / aws-us-gov partitions and role-paths.
        if (!/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(v.trim())) {
          return "Must look like arn:aws:iam::<account-id>:role/<RoleName>";
        }
        return null;
      },
      access_key_id: (v, values) => {
        const required = values.type === "credentials" || values.type === "s3_compatible";
        if (!required) return null;
        if (!v || v.trim().length === 0) return "Required";
        // Format check applies only to plain AWS credentials. S3-compatible
        // services (R2, MinIO, Wasabi…) use arbitrary key formats.
        if (values.type === "credentials" && !/^(AKIA|ASIA)[A-Z0-9]{16}$/.test(v.trim())) {
          return "AWS access key IDs start with AKIA or ASIA followed by 16 uppercase chars";
        }
        return null;
      },
      secret_access_key: (v, values) =>
        (values.type === "credentials" || values.type === "s3_compatible") &&
        (!v || v.trim().length === 0)
          ? "Required"
          : null,
      endpoint_url: (v, values) =>
        values.type === "s3_compatible" && (!v || v.trim().length === 0)
          ? "Required for s3_compatible type"
          : null,
    },
  });

  const goNext = (): void => {
    // Step 1 → validate name (type has a default and can't be cleared).
    // Don't run full form.validate() here — that would also flag still-empty
    // credential fields whose Step 2 inputs the user hasn't seen yet.
    if (active === 0) {
      const nameResult = form.validateField("name");
      if (nameResult.hasError) return;
      setActive(1);
      return;
    }
    if (active === 1) {
      // Validate credential / scope fields before reaching Review (server
      // returns 400 if anything required for the chosen type is missing —
      // fail-fast in UI).
      const result = form.validate();
      if (result.hasErrors) return;
    }
    setActive((a) => Math.min(a + 1, 2));
  };

  const goPrev = (): void => {
    setActive((a) => Math.max(a - 1, 0));
  };

  const onSave = (): void => {
    if (!config) return;
    if (config.roles.some((r) => r.name === form.values.name)) {
      notifications.show({
        message: `A role named "${form.values.name}" already exists.`,
        color: "red",
      });
      setActive(0);
      return;
    }
    // Drop any fields not applicable to the chosen type — prevents stale
    // credentials from a prior type selection leaking into the saved role.
    const newRole = stripIrrelevantFields(form.values);
    const updated: AppConfig = {
      ...toWritableConfig(config),
      roles: [...config.roles, newRole],
    };
    runWithToasts(
      save,
      updated,
      `Role ${newRole.name} created`,
      () => navigate("/admin/roles"),
    );
  };

  // Build the preview JSON with secret masked. Strip fields not applicable to
  // the chosen type — otherwise switching from credentials → default would
  // leave stale `access_key_id` / `secret_access_key` in the preview, which
  // doesn't match what `onSave` actually persists (it strips them too).
  const previewRole = stripIrrelevantFields({ ...form.values });
  if (previewRole.secret_access_key) {
    previewRole.secret_access_key = REDACTED;
  }
  const previewJson = JSON.stringify(previewRole, null, 2);

  return (
    <Stack gap="md">
      <Title order={2}>New role</Title>
      <Stepper
        active={active}
        // Allow only stepping back — forward navigation goes through goNext which validates.
        onStepClick={(s) => { if (s < active) setActive(s); }}
        maw={720}
      >
        <Stepper.Step label="Choose type" description="Pick role kind">
          <Stack gap="md" mt="md">
            <RoleFormFields form={form} mode="create" step="type" />
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Scope & details" description="Buckets, credentials, description">
          <Stack gap="md" mt="md">
            <RoleFormFields form={form} mode="create" step="credentials" />
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Review & save" description="Confirm and save">
          <Stack gap="md" mt="md">
            <Title order={4}>Review</Title>
            <JsonInput
              label="Role JSON (secret_access_key masked)"
              autosize
              minRows={8}
              value={previewJson}
              readOnly
            />
          </Stack>
        </Stepper.Step>
      </Stepper>

      <Group>
        {active > 0 && (
          <Button variant="subtle" onClick={goPrev}>Previous</Button>
        )}
        {active < 2 && (
          <Button onClick={goNext}>Next</Button>
        )}
        {active === 2 && (
          <Button onClick={onSave} loading={save.isPending}>Save role</Button>
        )}
        <Button variant="subtle" onClick={() => navigate("/admin/roles")}>
          Cancel
        </Button>
      </Group>
    </Stack>
  );
}
