import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Stack,
  Table,
  Title,
  Tooltip,
} from "@mantine/core";
import { KeyRound, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useMe } from "@/features/auth/hooks/useMe";
import {
  useAdminUsers,
  useCreateUser,
  useDeleteUser,
  useResetUserPassword,
  useUpdateUser,
} from "@/features/admin/hooks/useAdminUsers";
import {
  UserDrawer,
  type UserDrawerCreatePayload,
  type UserDrawerEditPayload,
} from "@/components/Admin/UserDrawer";
import { ResetPasswordModal } from "@/components/Admin/ResetPasswordModal";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { getErrorMessage } from "@/utils/apiError";
import { runWithToasts } from "@/utils/mutationToast";
import type { AdminUser } from "@/types/api";
import classes from "@/components/rowActions.module.css";

export function UsersPage() {
  const { data: me } = useMe();
  const { data: usersResponse, isLoading, error } = useAdminUsers();
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();
  const resetPwd = useResetUserPassword();

  const [drawerMode, setDrawerMode] = useState<"create" | "edit" | null>(null);
  const [editTarget, setEditTarget] = useState<AdminUser | undefined>();
  const [resetTarget, setResetTarget] = useState<AdminUser | undefined>();
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | undefined>();
  // Remember the last open mode so the drawer keeps its layout during the
  // close-animation (~250ms) instead of flipping to "create" via the
  // `?? "create"` fallback in the JSX.
  const lastDrawerMode = useRef<"create" | "edit" | null>(null);
  useEffect(() => {
    if (drawerMode !== null) lastDrawerMode.current = drawerMode;
  }, [drawerMode]);

  if (isLoading) return null;

  if (error) {
    return (
      <EmptyState
        tone="warning"
        title="Couldn't load users"
        description={getErrorMessage(error)}
      />
    );
  }

  const users = usersResponse?.users ?? [];
  const availableRoles = usersResponse?.available_roles ?? [];
  const currentUsername = me?.username ?? "";

  const onCreateSubmit = (payload: UserDrawerCreatePayload): void => {
    const username = payload.username;
    runWithToasts(
      createUser,
      {
        username,
        password: payload.password,
        is_admin: payload.is_admin,
        allowed_roles: payload.allowed_roles,
        must_change_password: payload.must_change_password,
      },
      `User ${username} created`,
      () => setDrawerMode(null),
    );
  };

  const onEditSubmit = (payload: UserDrawerEditPayload): void => {
    const username = payload.username;
    runWithToasts(
      updateUser,
      {
        username,
        payload: {
          is_admin: payload.is_admin,
          allowed_roles: payload.allowed_roles,
        },
      },
      `User ${username} updated`,
      () => {
        setDrawerMode(null);
        setEditTarget(undefined);
      },
    );
  };

  const onConfirmDelete = (): void => {
    if (!deleteTarget) return;
    const username = deleteTarget.username;
    runWithToasts(deleteUser, username, `User ${username} deleted`, () =>
      setDeleteTarget(undefined),
    );
  };

  const onResetSubmit = (
    newPassword: string,
    mustChangePassword: boolean,
  ): void => {
    if (!resetTarget) return;
    const username = resetTarget.username;
    runWithToasts(
      resetPwd,
      { username, newPassword, mustChangePassword },
      `Password reset for ${username}`,
      () => setResetTarget(undefined),
    );
  };

  return (
    <Stack gap="md">
      <Group justify="space-between" align="center">
        <Title order={2}>Users</Title>
        <Button
          leftSection={<Plus size={16} />}
          onClick={() => {
            setEditTarget(undefined);
            setDrawerMode("create");
          }}
        >
          Add user
        </Button>
      </Group>

      <Table highlightOnHover striped="even" verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Username</Table.Th>
            <Table.Th w={100}>Admin</Table.Th>
            <Table.Th>Roles</Table.Th>
            <Table.Th w={200}>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {users.map((u) => {
            const isSelf = u.username === currentUsername;
            return (
              <Table.Tr key={u.username} className={classes.row}>
                <Table.Td>{u.username}</Table.Td>
                <Table.Td>
                  {u.is_admin && <Badge color="mutedSlateBlue">admin</Badge>}
                </Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {u.allowed_roles.map((r) => (
                      <Badge key={r} variant="light" size="sm">
                        {r}
                      </Badge>
                    ))}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Group gap={4} className={classes.actions}>
                    <Tooltip label="Edit">
                      <ActionIcon
                        variant="subtle"
                        aria-label={`Edit ${u.username}`}
                        onClick={() => {
                          setEditTarget(u);
                          setDrawerMode("edit");
                        }}
                      >
                        <Pencil size={16} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip
                      label={
                        isSelf
                          ? "Use 'Change password' in the user menu"
                          : "Reset password"
                      }
                    >
                      <span>
                        <ActionIcon
                          variant="subtle"
                          aria-label={`Reset password for ${u.username}`}
                          disabled={isSelf}
                          onClick={() => setResetTarget(u)}
                        >
                          <KeyRound size={16} />
                        </ActionIcon>
                      </span>
                    </Tooltip>
                    <Tooltip
                      label={isSelf ? "You can't delete yourself" : "Delete"}
                    >
                      <span>
                        <ActionIcon
                          variant="subtle"
                          color="red"
                          aria-label={`Delete ${u.username}`}
                          disabled={isSelf}
                          onClick={() => setDeleteTarget(u)}
                        >
                          <Trash2 size={16} />
                        </ActionIcon>
                      </span>
                    </Tooltip>
                  </Group>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>

      <UserDrawer
        opened={drawerMode !== null}
        // Keep the last open mode while the drawer slides out — flipping to
        // "create" via `?? "create"` would briefly render the password input
        // + requirements list during the ~250ms close animation, flashing
        // red between Administrator and Allowed roles.
        mode={drawerMode ?? lastDrawerMode.current ?? "create"}
        initialUser={editTarget}
        currentUsername={currentUsername}
        availableRoles={availableRoles}
        onClose={() => {
          setDrawerMode(null);
          setEditTarget(undefined);
        }}
        onSubmit={(p) =>
          p.mode === "create" ? onCreateSubmit(p) : onEditSubmit(p)
        }
        loading={createUser.isPending || updateUser.isPending}
      />

      <ResetPasswordModal
        opened={resetTarget !== undefined}
        username={resetTarget?.username}
        onClose={() => setResetTarget(undefined)}
        onSubmit={onResetSubmit}
        loading={resetPwd.isPending}
      />

      <ConfirmDeleteModal
        opened={deleteTarget !== undefined}
        onClose={() => setDeleteTarget(undefined)}
        onConfirm={onConfirmDelete}
        items={deleteTarget ? [deleteTarget.username] : []}
        loading={deleteUser.isPending}
      />
    </Stack>
  );
}
