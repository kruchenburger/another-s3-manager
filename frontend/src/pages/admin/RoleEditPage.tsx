import { Button, Group, Stack, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useForm } from "@mantine/form";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { stripIrrelevantFields } from "@/features/admin/api/roleShape";
import { RoleFormFields } from "@/components/Admin/RoleFormFields";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { AppConfig, AppRole } from "@/types/api";

export function RoleEditPage() {
  const { roleName } = useParams<{ roleName: string }>();
  const decoded = decodeURIComponent(roleName ?? "");
  const navigate = useNavigate();
  const { data: config, isLoading, error } = useAdminConfig();
  const save = useSaveConfig();

  const form = useForm<AppRole>({
    initialValues: { name: "", type: "default" } as AppRole,
  });

  useEffect(() => {
    if (!config) return;
    const role = config.roles.find((r) => r.name === decoded);
    if (!role) {
      notifications.show({
        message: `Role "${decoded}" not found`,
        color: "red",
      });
      navigate("/admin/roles", { replace: true });
      return;
    }
    // Show empty secret_access_key in the input (placeholder will hint to leave
    // blank to preserve). On submit, if user didn't enter a new value, we
    // re-attach the original secret from `existing` below.
    const populated = { ...role, secret_access_key: "" };
    form.setInitialValues(populated);
    form.setValues(populated);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, decoded]);

  if (isLoading) return null;

  if (error) {
    return (
      <EmptyState
        tone="warning"
        title="Couldn't load roles"
        description={getErrorMessage(error)}
      />
    );
  }

  if (!config) return null;

  const readOnly = config.is_read_only === true;

  const onSubmit = form.onSubmit((values) => {
    const existing = config.roles.find((r) => r.name === decoded);
    if (!existing) return;
    // Preserve existing secret if the user didn't enter a new one
    const merged: AppRole = {
      ...values,
      secret_access_key:
        values.secret_access_key && values.secret_access_key.trim() !== ""
          ? values.secret_access_key
          : existing.secret_access_key,
    };
    // Strip fields that don't apply to the role's current type (avoids
    // persisting stale credentials e.g. when type was changed mid-edit).
    const cleaned = stripIrrelevantFields(merged);
    const next: AppConfig = {
      ...toWritableConfig(config),
      roles: config.roles.map((r) => (r.name === decoded ? cleaned : r)),
    };
    runWithToasts(save, next, `Role ${values.name} saved`, () => navigate("/admin/roles"));
  });

  return (
    <Stack gap="md">
      <Title order={2}>Edit role: {decoded}</Title>
      <form onSubmit={onSubmit}>
        <Stack gap="md" maw={620}>
          <RoleFormFields form={form} disabled={readOnly} mode="edit" step="all" />
          <Group>
            <Button type="submit" disabled={readOnly} loading={save.isPending}>
              Save changes
            </Button>
            <Button variant="subtle" onClick={() => navigate("/admin/roles")}>
              Cancel
            </Button>
          </Group>
        </Stack>
      </form>
    </Stack>
  );
}
