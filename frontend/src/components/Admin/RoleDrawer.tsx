import {
  Button,
  Drawer,
  Group,
  JsonInput,
  Stack,
  Stepper,
  Title,
} from "@mantine/core";
import { useEffect, useState } from "react";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { stripIrrelevantFields } from "@/features/admin/api/roleShape";
import { RoleFormFields } from "@/components/Admin/RoleFormFields";
import type { AppConfig, AppRole } from "@/types/api";

const REDACTED = "***REDACTED***";

interface RoleDrawerProps {
  opened: boolean;
  mode: "create" | "edit";
  initialRole?: AppRole;
  config: AppConfig | undefined;
  readOnly: boolean;
  onClose: () => void;
  onSubmit: (
    role: AppRole,
    opts: { mode: "create" | "edit"; previousName?: string },
  ) => void;
  loading?: boolean;
}

/**
 * Unified Drawer for creating and editing roles.
 *
 * Create mode: 3-step Stepper (Choose type / Scope & details / Review & save).
 * Edit mode: single-page form with the picker locked to the role's type.
 *
 * Validators are mostly shared with the legacy RoleNewPage. The format checks
 * (AKIA-only access_key_id, ARN regex) run only when mode === "create" — a
 * legacy role saved before those checks landed (e.g. an ASIA-prefixed key)
 * must not be blocked from re-saving in edit mode. Presence checks ("Required")
 * still run in both modes.
 *
 * The drawer owns no URL routing — opening, closing, and routing are the
 * parent's job. It also does NOT merge secrets: in edit mode the drawer emits
 * whatever the user typed (or "" if they didn't), and the parent merges with
 * the existing role's secret_access_key before saving.
 */
export function RoleDrawer({
  opened,
  mode,
  initialRole,
  config,
  readOnly,
  onClose,
  onSubmit,
  loading,
}: RoleDrawerProps) {
  const [active, setActive] = useState(0);

  const form = useForm<AppRole>({
    initialValues: {
      name: "",
      type: "default",
      use_ssl: true,
      verify_ssl: true,
      addressing_style: "auto",
      allowed_buckets: [],
      // avoid PasswordInput controlled→uncontrolled warning when user starts typing
      secret_access_key: "",
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
        // Format check is create-only — editing a legacy role with an
        // out-of-spec ARN must not block save.
        if (mode !== "create") return null;
        // IAM Role ARN: arn:aws:iam::<12-digit-account>:role/<RoleName>
        // Allows aws-cn / aws-us-gov partitions and role-paths.
        if (!/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(v.trim())) {
          return "Must look like arn:aws:iam::<account-id>:role/<RoleName>";
        }
        return null;
      },
      access_key_id: (v, values) => {
        const required =
          values.type === "credentials" || values.type === "s3_compatible";
        if (!required) return null;
        if (!v || v.trim().length === 0) return "Required";
        // Same rationale as role_arn: format check create-only. A legacy
        // ASIA-prefixed credentials role saved before the AKIA-only check
        // landed must still be editable without rewriting the key.
        if (mode !== "create") return null;
        // Format check applies only to plain AWS credentials. S3-compatible
        // services (R2, MinIO, Wasabi…) use arbitrary key formats.
        if (
          values.type === "credentials" &&
          !/^AKIA[A-Z0-9]{16}$/.test(v.trim())
        ) {
          return "Static AWS access key IDs start with AKIA followed by 16 uppercase chars. For temporary STS credentials use the 'STS assume role' type.";
        }
        return null;
      },
      secret_access_key: (v, values) =>
        (values.type === "credentials" || values.type === "s3_compatible") &&
        mode === "create" &&
        (!v || v.trim().length === 0)
          ? "Required"
          : null,
      endpoint_url: (v, values) =>
        values.type === "s3_compatible" && (!v || v.trim().length === 0)
          ? "Required for s3_compatible type"
          : null,
    },
  });

  // Populate form when the drawer opens or its inputs change. Edit mode shows
  // an empty secret_access_key (placeholder hints to leave blank to preserve);
  // the parent re-attaches the original secret on submit.
  useEffect(() => {
    if (!opened) return;
    if (mode === "edit" && initialRole) {
      const populated: AppRole = { ...initialRole, secret_access_key: "" };
      form.setInitialValues(populated);
      form.setValues(populated);
    } else if (mode === "create") {
      form.reset();
      setActive(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened, mode, initialRole]);

  const goNext = (): void => {
    // Step 1 → validate name only. Don't run full form.validate() here — that
    // would also flag still-empty credential fields whose Step 2 inputs the
    // user hasn't seen yet.
    if (active === 0) {
      const nameResult = form.validateField("name");
      if (nameResult.hasError) return;
      setActive(1);
      return;
    }
    if (active === 1) {
      const result = form.validate();
      if (result.hasErrors) return;
    }
    setActive((a) => Math.min(a + 1, 2));
  };

  const goPrev = (): void => {
    setActive((a) => Math.max(a - 1, 0));
  };

  const onCreate = (): void => {
    if (!config) return;
    if (config.roles.some((r) => r.name === form.values.name)) {
      notifications.show({
        message: `A role named "${form.values.name}" already exists.`,
        color: "red",
      });
      setActive(0);
      return;
    }
    onSubmit(stripIrrelevantFields(form.values), { mode: "create" });
  };

  const onEditFormSubmit = form.onSubmit((values) => {
    onSubmit(stripIrrelevantFields(values), {
      mode: "edit",
      previousName: initialRole?.name,
    });
  });

  // Build the preview JSON with secret masked. Strip fields not applicable to
  // the chosen type — otherwise switching from credentials → default would
  // leave stale credentials in the preview that don't match what `onCreate`
  // actually persists.
  const previewRole = stripIrrelevantFields({ ...form.values });
  if (previewRole.secret_access_key) {
    previewRole.secret_access_key = REDACTED;
  }
  const previewJson = JSON.stringify(previewRole, null, 2);

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="xl"
      title={
        mode === "create"
          ? "Create role"
          : `Edit role: ${initialRole?.name ?? ""}`
      }
      // Make the drawer body a flex column so the form can stretch and the
      // footer can stick to the bottom regardless of content height.
      // `calc(100% - 60px)` accounts for the Mantine Drawer header.
      styles={{
        body: {
          display: "flex",
          flexDirection: "column",
          height: "calc(100% - 60px)",
          overflow: "hidden",
        },
      }}
    >
      {mode === "create" ? (
        <>
          <Stack
            gap="md"
            style={{ flex: 1, overflowY: "auto", paddingRight: 4 }}
          >
            <Stepper
              active={active}
              // Allow only stepping back — forward navigation goes through
              // goNext which validates.
              onStepClick={(s) => {
                if (s < active) setActive(s);
              }}
            >
              <Stepper.Step label="Choose type" description="Pick role kind">
                <Stack gap="md" mt="md">
                  <RoleFormFields form={form} mode="create" step="type" />
                </Stack>
              </Stepper.Step>
              <Stepper.Step
                label="Scope & details"
                description="Buckets, credentials, description"
              >
                <Stack gap="md" mt="md">
                  <RoleFormFields
                    form={form}
                    mode="create"
                    step="credentials"
                  />
                </Stack>
              </Stepper.Step>
              <Stepper.Step
                label="Review & save"
                description="Confirm and save"
              >
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
          </Stack>
          <div
            style={{
              paddingTop: 12,
              marginTop: 12,
              borderTop: "1px solid var(--mantine-color-default-border)",
            }}
          >
            <Group justify="space-between">
              <Button variant="subtle" onClick={onClose}>
                Cancel
              </Button>
              <Group>
                {active > 0 && (
                  <Button variant="subtle" onClick={goPrev}>
                    Previous
                  </Button>
                )}
                {active < 2 && <Button onClick={goNext}>Next</Button>}
                {active === 2 && (
                  <Button onClick={onCreate} loading={loading}>
                    Save role
                  </Button>
                )}
              </Group>
            </Group>
          </div>
        </>
      ) : (
        <form
          onSubmit={onEditFormSubmit}
          style={{
            display: "flex",
            flexDirection: "column",
            flex: 1,
            minHeight: 0,
          }}
        >
          <Stack
            gap="md"
            style={{ flex: 1, overflowY: "auto", paddingRight: 4 }}
          >
            <RoleFormFields
              form={form}
              disabled={readOnly}
              mode="edit"
              step="all"
            />
          </Stack>
          <div
            style={{
              paddingTop: 12,
              marginTop: 12,
              borderTop: "1px solid var(--mantine-color-default-border)",
            }}
          >
            <Group justify="space-between">
              <Button variant="subtle" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={readOnly} loading={loading}>
                Save changes
              </Button>
            </Group>
          </div>
        </form>
      )}
    </Drawer>
  );
}
