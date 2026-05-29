import { useState } from "react";
import { Alert, Button, Group, Select, Stack, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { AlertTriangle, Plus } from "lucide-react";
import { useAdminTokens } from "@/features/tokens/hooks/useAdminTokens";
import { useCreateAdminToken } from "@/features/tokens/hooks/useCreateToken";
import { useDeleteAdminToken } from "@/features/tokens/hooks/useDeleteToken";
import { useUpdateAdminToken } from "@/features/tokens/hooks/useUpdateToken";
import { useAdminUsers } from "@/features/admin/hooks/useAdminUsers";
import { TokensTable } from "@/components/Tokens/TokensTable";
import { CreateTokenDrawer } from "@/components/Tokens/CreateTokenDrawer";
import { TokenEditDrawer } from "@/components/Tokens/TokenEditDrawer";
import { TokenPlaintextModal } from "@/components/Tokens/TokenPlaintextModal";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { QueryErrorState } from "@/components/QueryErrorState/QueryErrorState";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { ApiToken, ApiTokenWithOwner, ApiTokenWithPlaintext, CreateTokenPayload } from "@/types/api";

export function AdminApiTokensPage() {
  const { data: tokensData, isLoading: tokensLoading, error: tokensError } = useAdminTokens();
  const { data: usersData, error: usersError } = useAdminUsers();
  const createMutation = useCreateAdminToken();
  const deleteMutation = useDeleteAdminToken();
  const updateMutation = useUpdateAdminToken();

  const [createOpen, create] = useDisclosure(false);
  const [plaintextResult, setPlaintextResult] = useState<(ApiTokenWithPlaintext & { owner_username: string }) | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<ApiToken | null>(null);
  const [editTarget, setEditTarget] = useState<ApiTokenWithOwner | null>(null);
  const [userFilter, setUserFilter] = useState<string | null>(null);

  const allTokens: ApiTokenWithOwner[] = tokensData?.tokens ?? [];
  const users = usersData?.users ?? [];

  const filtered = userFilter
    ? allTokens.filter((t) => t.owner_username === userFilter)
    : allTokens;

  function handleCreate(payload: CreateTokenPayload, userId?: number) {
    if (!userId) return;
    const selectedUser = users.find((u) => u.id === userId);
    createMutation.mutate(
      { ...payload, user_id: userId },
      {
        onSuccess: (token) => {
          notifications.show({ title: "Success", message: "Token created", color: "green" });
          create.close();
          setPlaintextResult({
            ...token,
            owner_username: selectedUser?.username ?? String(userId),
          });
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
  }

  function handleRevoke() {
    if (!revokeTarget) return;
    runWithToasts(deleteMutation, revokeTarget.id, `Token "${revokeTarget.name}" revoked`, () => {
      setRevokeTarget(null);
    });
  }

  const adminNote = plaintextResult
    ? `Pass this token to ${plaintextResult.owner_username} via a secure channel (e.g. password manager share).`
    : undefined;

  return (
    <Stack gap="md">
        {tokensError ? (
          <QueryErrorState error={tokensError} title="Couldn't load tokens" />
        ) : (
          <>
            <Group justify="space-between">
              <Title order={2}>MCP tokens</Title>
              <Button leftSection={<Plus size={16} />} onClick={create.open}>
                Issue token on behalf of user
              </Button>
            </Group>

            {usersError && (
              <Alert
                icon={<AlertTriangle size={16} />}
                color="yellow"
                title="User filter unavailable"
              >
                {getErrorMessage(usersError)}
              </Alert>
            )}

            <Group>
              <Select
                label="User"
                placeholder={usersError ? "Failed to load users" : "All users"}
                clearable
                searchable
                disabled={!!usersError}
                data={users.map((u) => ({ value: u.username, label: u.username }))}
                value={userFilter}
                onChange={setUserFilter}
              />
            </Group>

            {!tokensLoading && (
              <TokensTable
                tokens={filtered}
                showOwner
                onRevoke={(t) => setRevokeTarget(t)}
                onEdit={(t) => setEditTarget(t as ApiTokenWithOwner)}
              />
            )}
          </>
        )}
      <CreateTokenDrawer
        opened={createOpen}
        onClose={create.close}
        onSubmit={handleCreate}
        loading={createMutation.isPending}
        used={0}
        limit={Infinity}
        adminMode
        availableUsers={users.map((u) => ({ id: u.id, username: u.username }))}
      />

      {plaintextResult && (
        <TokenPlaintextModal
          opened
          onClose={() => setPlaintextResult(null)}
          plaintext={plaintextResult.token_plaintext}
          noteForAdmin={adminNote}
        />
      )}

      <ConfirmDeleteModal
        opened={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
        items={revokeTarget ? [`token "${revokeTarget.name}"`] : []}
        loading={deleteMutation.isPending}
      />

      <TokenEditDrawer
        opened={editTarget !== null}
        onClose={() => setEditTarget(null)}
        loading={updateMutation.isPending}
        token={editTarget}
        onSubmit={(payload) => {
          if (!editTarget) return;
          runWithToasts(
            updateMutation,
            { id: editTarget.id, payload },
            `Token "${editTarget.name}" updated`,
            () => setEditTarget(null),
          );
        }}
      />
    </Stack>
  );
}
