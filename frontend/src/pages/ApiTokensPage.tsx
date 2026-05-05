import { useState } from "react";
import { Button, Container, Group, Stack, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Plus } from "lucide-react";
import { useMyTokens } from "@/features/tokens/hooks/useMyTokens";
import { useCreateMyToken } from "@/features/tokens/hooks/useCreateToken";
import { useDeleteMyToken } from "@/features/tokens/hooks/useDeleteToken";
import { TokensTable } from "@/components/Tokens/TokensTable";
import { CreateTokenModal } from "@/components/Tokens/CreateTokenModal";
import { TokenPlaintextModal } from "@/components/Tokens/TokenPlaintextModal";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { notifications } from "@mantine/notifications";
import { runWithToasts } from "@/utils/mutationToast";
import { getErrorMessage } from "@/utils/apiError";
import type { ApiToken, ApiTokenWithPlaintext, CreateTokenPayload } from "@/types/api";

export function ApiTokensPage() {
  const { data, isLoading } = useMyTokens();
  const createMutation = useCreateMyToken();
  const deleteMutation = useDeleteMyToken();

  const [createOpen, create] = useDisclosure(false);
  const [plaintextResult, setPlaintextResult] = useState<ApiTokenWithPlaintext | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<ApiToken | null>(null);

  const tokens = data?.tokens ?? [];

  function handleCreate(payload: CreateTokenPayload) {
    // Use mutate directly to capture the token plaintext from onSuccess data.
    createMutation.mutate(payload, {
      onSuccess: (token) => {
        notifications.show({ title: "Success", message: "Token created", color: "green" });
        create.close();
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
    });
  }

  function handleRevoke() {
    if (!revokeTarget) return;
    runWithToasts(
      deleteMutation,
      revokeTarget.id,
      `Token "${revokeTarget.name}" revoked`,
      () => {
        setRevokeTarget(null);
      },
    );
  }

  return (
    <Container size="lg" py="lg">
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={2}>API tokens</Title>
          <Button leftSection={<Plus size={16} />} onClick={create.open}>
            Create token
          </Button>
        </Group>
        {data && (
          <Text size="sm" c="dimmed">
            Used {data.used} of {data.limit} token slots
          </Text>
        )}
        {!isLoading && (
          <TokensTable tokens={tokens} onRevoke={(t) => setRevokeTarget(t)} />
        )}
      </Stack>

      <CreateTokenModal
        opened={createOpen}
        onClose={create.close}
        onSubmit={handleCreate}
        loading={createMutation.isPending}
        used={data?.used ?? 0}
        limit={data?.limit ?? 10}
      />

      {plaintextResult && (
        <TokenPlaintextModal
          opened
          onClose={() => setPlaintextResult(null)}
          plaintext={plaintextResult.token_plaintext}
        />
      )}

      <ConfirmDeleteModal
        opened={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={handleRevoke}
        items={revokeTarget ? [`token "${revokeTarget.name}"`] : []}
        loading={deleteMutation.isPending}
      />
    </Container>
  );
}
