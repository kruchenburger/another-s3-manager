import { Badge, Button, Group, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { AlertTriangle, Plus, Pencil, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useMatch, useNavigate } from "react-router-dom";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { stripIrrelevantFields } from "@/features/admin/api/roleShape";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { RoleDrawer } from "@/components/Admin/RoleDrawer";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { AppConfig, AppRole } from "@/types/api";

export function RolesPage() {
  const { data: config, isLoading, error } = useAdminConfig();
  const save = useSaveConfig();
  const navigate = useNavigate();
  const [deleteTarget, setDeleteTarget] = useState<AppRole | undefined>();

  // URL → drawer mode. /admin/roles/new opens the create drawer; any other
  // /admin/roles/:roleName opens the edit drawer pre-filled. Both URL patterns
  // ALSO match the dynamic `:roleName` route (because :roleName captures the
  // literal string "new"), so disambiguate by preferring the more specific
  // /new match.
  const newMatch = useMatch("/admin/roles/new");
  const editMatch = useMatch("/admin/roles/:roleName");
  const isNewRoute = newMatch !== null;
  const editRoleName =
    !isNewRoute && editMatch
      ? decodeURIComponent(editMatch.params.roleName ?? "")
      : null;

  const drawerMode: "create" | "edit" | null = isNewRoute
    ? "create"
    : editRoleName
      ? "edit"
      : null;

  // Keep the last opened mode around so the drawer keeps its layout during the
  // close-animation (Mantine Drawer animates out over ~250ms — a sudden mode
  // flip mid-animation flashes the wrong content).
  const lastDrawerMode = useRef<"create" | "edit" | null>(null);
  useEffect(() => {
    if (drawerMode !== null) lastDrawerMode.current = drawerMode;
  }, [drawerMode]);
  const renderMode = drawerMode ?? lastDrawerMode.current ?? "create";

  const editRole =
    editRoleName && config
      ? config.roles.find((r) => r.name === editRoleName)
      : undefined;

  // Not-found redirect: if the URL points at a role that doesn't exist in the
  // loaded config, bounce back to the list and notify. We can only do this
  // once `config` is loaded — otherwise we'd false-trigger during the load.
  useEffect(() => {
    if (editRoleName && config && !editRole) {
      notifications.show({
        message: `Role "${editRoleName}" not found`,
        color: "red",
      });
      navigate("/admin/roles", { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editRoleName, config]);

  const onSubmitRole = (
    role: AppRole,
    opts: { mode: "create" | "edit"; previousName?: string },
  ): void => {
    if (!config) return;

    if (opts.mode === "create") {
      const next: AppConfig = {
        ...toWritableConfig(config),
        roles: [...config.roles, role],
      };
      runWithToasts(save, next, `Role ${role.name} created`, () =>
        navigate("/admin/roles"),
      );
      return;
    }

    // Edit mode: drawer emits whatever the user typed, including empty
    // secret_access_key. Preserve the existing secret if the user didn't
    // enter a new one. Mirrors the previous RoleEditPage behaviour.
    const existing = config.roles.find((r) => r.name === opts.previousName);
    if (!existing) return;
    const merged: AppRole = {
      ...role,
      secret_access_key:
        role.secret_access_key && role.secret_access_key.trim() !== ""
          ? role.secret_access_key
          : existing.secret_access_key,
    };
    const cleaned = stripIrrelevantFields(merged);
    const next: AppConfig = {
      ...toWritableConfig(config),
      roles: config.roles.map((r) =>
        r.name === opts.previousName ? cleaned : r,
      ),
    };
    runWithToasts(save, next, `Role ${role.name} saved`, () =>
      navigate("/admin/roles"),
    );
  };

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

  const onConfirmDelete = (): void => {
    if (!deleteTarget) return;
    const targetName = deleteTarget.name;
    const next: AppConfig = {
      ...toWritableConfig(config),
      roles: config.roles.filter((r) => r.name !== targetName),
    };
    runWithToasts(save, next, `Role ${targetName} deleted`, () => setDeleteTarget(undefined));
  };

  // Visual: amber for credentials-bearing types (signal "needs secrets care"),
  // slate for everything else.
  const typeColor = (t: AppRole["type"]): string =>
    t === "credentials" || t === "s3_compatible" ? "amber" : "gray";

  return (
    <Stack gap="md">
      {config.roles.length === 0 ? (
        <EmptyState
          title="No roles defined"
          description="Click 'Add role' to create your first role."
          cta={
            !readOnly ? (
              <Button leftSection={<Plus size={16} />} onClick={() => navigate("/admin/roles/new")}>
                Add role
              </Button>
            ) : undefined
          }
        />
      ) : (
        <>
          <Group justify="space-between" align="center">
            <Title order={2}>Roles</Title>
            <Button
              leftSection={<Plus size={16} />}
              disabled={readOnly}
              onClick={() => navigate("/admin/roles/new")}
            >
              Add role
            </Button>
          </Group>

          <Table highlightOnHover striped="even" verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th w={140}>Type</Table.Th>
                <Table.Th w={140}>Buckets</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th w={140}>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {config.roles.map((r) => (
                <Table.Tr key={r.name}>
                  <Table.Td>{r.name}</Table.Td>
                  <Table.Td>
                    <Badge color={typeColor(r.type)} variant="light">{r.type}</Badge>
                  </Table.Td>
                  <Table.Td>
                    {(r.allowed_buckets?.length ?? 0) === 0 ? (
                      <Tooltip label="This role has no buckets configured — users with only this role will see an empty bucket list.">
                        <Badge
                          color="orange"
                          variant="filled"
                          leftSection={<AlertTriangle size={12} />}
                        >
                          No buckets
                        </Badge>
                      </Tooltip>
                    ) : (
                      <Text size="sm" c="dimmed">
                        {r.allowed_buckets!.length} buckets
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" lineClamp={1}>{r.description ?? ""}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      <Button
                        size="xs"
                        variant="subtle"
                        aria-label={`Edit ${r.name}`}
                        disabled={readOnly}
                        onClick={() => navigate(`/admin/roles/${encodeURIComponent(r.name)}`)}
                      >
                        <Pencil size={14} />
                      </Button>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        aria-label={`Delete ${r.name}`}
                        disabled={readOnly}
                        onClick={() => setDeleteTarget(r)}
                      >
                        <Trash2 size={14} />
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </>
      )}

      <ConfirmDeleteModal
        opened={deleteTarget !== undefined}
        onClose={() => setDeleteTarget(undefined)}
        onConfirm={onConfirmDelete}
        items={deleteTarget ? [deleteTarget.name] : []}
        loading={save.isPending}
      />

      <RoleDrawer
        opened={drawerMode !== null}
        mode={renderMode}
        initialRole={editRole}
        config={config}
        readOnly={readOnly}
        onClose={() => navigate("/admin/roles")}
        onSubmit={onSubmitRole}
        loading={save.isPending}
      />
    </Stack>
  );
}
