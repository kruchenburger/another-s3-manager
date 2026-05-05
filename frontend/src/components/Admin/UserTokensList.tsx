import { useState } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { useAdminTokens } from "@/features/tokens/hooks/useAdminTokens";
import { useUpdateAdminToken } from "@/features/tokens/hooks/useUpdateToken";
import { useDeleteAdminToken } from "@/features/tokens/hooks/useDeleteToken";
import { useCreateAdminToken } from "@/features/tokens/hooks/useCreateToken";
import { CreateTokenModal } from "@/components/Tokens/CreateTokenModal";
import { EditTokenModal } from "@/components/Tokens/EditTokenModal";
import { runWithToasts } from "@/utils/mutationToast";
import type { ApiTokenWithOwner } from "@/types/api";

interface UserTokensListProps {
  username: string;
  userId: number;
}

function formatLastUsed(value: string | null): string {
  if (!value) return "Never";
  return new Date(value).toLocaleString();
}

export function UserTokensList({ username, userId }: UserTokensListProps) {
  const { data, isLoading } = useAdminTokens();
  const tokens = (data?.tokens ?? []).filter(
    (t) => t.owner_username === username,
  );

  const [createOpened, setCreateOpened] = useState(false);
  const [editTarget, setEditTarget] = useState<ApiTokenWithOwner | null>(null);

  const createMutation = useCreateAdminToken();
  const updateMutation = useUpdateAdminToken();
  const deleteMutation = useDeleteAdminToken();

  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <Title order={5}>MCP tokens</Title>
        <Button
          variant="light"
          size="xs"
          leftSection={<Plus size={14} />}
          onClick={() => setCreateOpened(true)}
        >
          Issue token on behalf
        </Button>
      </Group>

      {isLoading ? (
        <Text size="sm" c="dimmed">
          Loading...
        </Text>
      ) : tokens.length === 0 ? (
        <Text size="sm" c="dimmed">
          No tokens issued yet.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Read-only</Table.Th>
              <Table.Th>Last used</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.map((t) => (
              <Table.Tr key={t.id}>
                <Table.Td>{t.name}</Table.Td>
                <Table.Td>
                  {t.is_read_only ? (
                    <Badge>Yes</Badge>
                  ) : (
                    <Badge color="orange">No</Badge>
                  )}
                </Table.Td>
                <Table.Td>{formatLastUsed(t.last_used_at)}</Table.Td>
                <Table.Td>
                  <Group gap="xs" wrap="nowrap">
                    <ActionIcon
                      variant="subtle"
                      aria-label={`Edit ${t.name}`}
                      onClick={() => setEditTarget(t)}
                    >
                      <Pencil size={14} />
                    </ActionIcon>
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      aria-label={`Revoke ${t.name}`}
                      onClick={() =>
                        runWithToasts(
                          deleteMutation,
                          t.id,
                          `Token "${t.name}" revoked`,
                        )
                      }
                    >
                      <Trash2 size={14} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Text size="xs" c="dimmed">
        User can also manage their own tokens at /v2/api-tokens.
      </Text>

      {createOpened && (
        <CreateTokenModal
          opened={createOpened}
          onClose={() => setCreateOpened(false)}
          adminMode
          availableUsers={[{ id: userId, username }]}
          loading={createMutation.isPending}
          // The CreateTokenModal in admin mode passes the picked user_id back to onSubmit;
          // since we hard-pin the picker to a single user, userId arg always equals our userId prop.
          // Slot indicator is hidden for admin mode (Phase 5 fix); per-user limit is enforced server-side.
          used={0}
          limit={Infinity}
          onSubmit={(payload, pickedUserId) => {
            const targetId = pickedUserId ?? userId;
            createMutation.mutate(
              { ...payload, user_id: targetId },
              {
                onSuccess: () => setCreateOpened(false),
              },
            );
          }}
        />
      )}

      {editTarget && (
        <EditTokenModal
          opened
          onClose={() => setEditTarget(null)}
          loading={updateMutation.isPending}
          token={editTarget}
          onSubmit={(payload) =>
            runWithToasts(
              updateMutation,
              { id: editTarget.id, payload },
              `Token "${editTarget.name}" updated`,
              () => setEditTarget(null),
            )
          }
        />
      )}
    </Stack>
  );
}
