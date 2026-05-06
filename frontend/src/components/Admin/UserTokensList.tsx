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
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { useAdminTokens } from "@/features/tokens/hooks/useAdminTokens";
import { useUpdateAdminToken } from "@/features/tokens/hooks/useUpdateToken";
import { useDeleteAdminToken } from "@/features/tokens/hooks/useDeleteToken";
import { useCreateAdminToken } from "@/features/tokens/hooks/useCreateToken";
import { CreateTokenModal } from "@/components/Tokens/CreateTokenModal";
import { TokenEditDrawer } from "@/components/Tokens/TokenEditDrawer";
import { TokenPlaintextModal } from "@/components/Tokens/TokenPlaintextModal";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import { formatAbsolute, formatRelative } from "@/utils/formatDate";
import type {
  ApiTokenWithOwner,
  ApiTokenWithPlaintext,
} from "@/types/api";

interface UserTokensListProps {
  username: string;
  userId: number;
}

export function UserTokensList({ username, userId }: UserTokensListProps) {
  const { data, isLoading } = useAdminTokens();
  const tokens = (data?.tokens ?? []).filter(
    (t) => t.owner_username === username,
  );

  const [createOpened, setCreateOpened] = useState(false);
  const [editTarget, setEditTarget] = useState<ApiTokenWithOwner | null>(null);
  // Plaintext is returned by the create endpoint exactly once. We capture it
  // into state and render TokenPlaintextModal so the admin can hand it to the
  // user out-of-band — without this, the secret is silently lost.
  const [plaintextResult, setPlaintextResult] =
    useState<ApiTokenWithPlaintext | null>(null);

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
                <Table.Td>
                  <Tooltip
                    label={formatAbsolute(t.last_used_at)}
                    disabled={!t.last_used_at}
                  >
                    <span>{formatRelative(t.last_used_at)}</span>
                  </Tooltip>
                </Table.Td>
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
          // CreateTokenModal in admin mode passes the picked user_id back to onSubmit;
          // since the picker is hard-pinned to a single user, pickedUserId always
          // equals our userId prop. Slot indicator is hidden for admin mode (Phase 5);
          // per-user limit is enforced server-side.
          used={0}
          limit={Infinity}
          onSubmit={(payload, pickedUserId) => {
            const targetId = pickedUserId ?? userId;
            createMutation.mutate(
              { ...payload, user_id: targetId },
              {
                onSuccess: (token) => {
                  notifications.show({
                    title: "Success",
                    message: "Token created",
                    color: "green",
                  });
                  setCreateOpened(false);
                  setPlaintextResult(token);
                },
                onError: (e) => {
                  notifications.show({
                    title: "Error",
                    message: getErrorMessage(e),
                    color: "red",
                    autoClose: false,
                  });
                },
              },
            );
          }}
        />
      )}

      {plaintextResult && (
        <TokenPlaintextModal
          opened
          onClose={() => setPlaintextResult(null)}
          plaintext={plaintextResult.token_plaintext}
          noteForAdmin={`Pass this token to ${username} via a secure channel (e.g. password manager share).`}
        />
      )}

      {editTarget && (
        <TokenEditDrawer
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
