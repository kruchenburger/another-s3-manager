import { Button, Group, Modal, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import {
  useAdminBans,
  useUnbanUser,
} from "@/features/admin/hooks/useAdminBans";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { formatDate } from "@/utils/formatDate";
import { getErrorMessage } from "@/utils/apiError";
import { runWithToasts } from "@/utils/mutationToast";
import classes from "@/components/rowActions.module.css";

export function BansPage() {
  const { data: bans, isLoading, error } = useAdminBans();
  const unban = useUnbanUser();
  const [target, setTarget] = useState<string | null>(null);

  if (isLoading) return null;

  if (error) {
    return (
      <EmptyState
        tone="warning"
        title="Couldn't load bans"
        description={getErrorMessage(error)}
      />
    );
  }

  if (!bans || bans.length === 0) {
    return (
      <EmptyState
        title="No bans currently active"
        description="After 3 failed login attempts a user is banned for 1 hour. Admins are exempt."
      />
    );
  }

  const handleConfirm = (): void => {
    if (!target) return;
    const username = target;
    runWithToasts(unban, username, `Unbanned ${username}`, () =>
      setTarget(null),
    );
  };

  return (
    <Stack gap="md">
      <Title order={2}>Bans</Title>
      <Text c="dimmed">Users banned after repeated failed logins.</Text>
      <Table highlightOnHover striped="even" verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Username</Table.Th>
            <Table.Th>Banned until</Table.Th>
            <Table.Th>Reason</Table.Th>
            <Table.Th w={120}>Actions</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {bans.map((ban) => (
            <Table.Tr key={ban.username} className={classes.row}>
              <Table.Td>{ban.username}</Table.Td>
              <Table.Td>
                {formatDate(new Date(ban.banned_until * 1000).toISOString())}
              </Table.Td>
              <Table.Td>{ban.reason}</Table.Td>
              <Table.Td>
                <Button
                  size="xs"
                  variant="light"
                  className={classes.actions}
                  onClick={() => setTarget(ban.username)}
                >
                  Unban
                </Button>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>

      <Modal
        opened={target !== null}
        onClose={() => setTarget(null)}
        title="Unban user"
        centered
      >
        <Stack gap="md">
          <Text>
            Unban user{" "}
            <Text span fw={600}>
              {target}
            </Text>
            ?
          </Text>
          <Group justify="flex-end">
            <Button
              variant="default"
              onClick={() => setTarget(null)}
              disabled={unban.isPending}
            >
              Cancel
            </Button>
            <Button onClick={handleConfirm} loading={unban.isPending}>
              Unban
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
