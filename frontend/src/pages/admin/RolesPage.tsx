import { Badge, Button, Group, Stack, Table, Text, Title } from "@mantine/core";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAdminConfig, useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { toWritableConfig } from "@/features/admin/api/configShape";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { AppConfig, AppRole } from "@/types/api";

export function RolesPage() {
  const { data: config, isLoading, error } = useAdminConfig();
  const save = useSaveConfig();
  const navigate = useNavigate();
  const [deleteTarget, setDeleteTarget] = useState<AppRole | undefined>();

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

  if (config.roles.length === 0) {
    return (
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
    );
  }

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
            <Table.Th w={120}>Buckets</Table.Th>
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
                <Text size="sm" c="dimmed">
                  {(r.allowed_buckets?.length ?? 0)} buckets
                </Text>
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

      <ConfirmDeleteModal
        opened={deleteTarget !== undefined}
        onClose={() => setDeleteTarget(undefined)}
        onConfirm={onConfirmDelete}
        items={deleteTarget ? [deleteTarget.name] : []}
        loading={save.isPending}
      />
    </Stack>
  );
}
