import { ActionIcon, Badge, Group, Table, Text, Tooltip } from "@mantine/core";
import { Check, Pencil, Trash2 } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { formatAbsolute, formatRelative } from "@/utils/formatDate";
import type { ApiToken, ApiTokenWithOwner } from "@/types/api";
import classes from "@/components/rowActions.module.css";

interface TokensTableProps {
  tokens: (ApiToken | ApiTokenWithOwner)[];
  showOwner?: boolean;
  onRevoke: (token: ApiToken) => void;
  /** Optional. When provided, renders a Pencil ActionIcon next to Revoke. */
  onEdit?: (token: ApiToken) => void;
}

export function TokensTable({
  tokens,
  showOwner = false,
  onRevoke,
  onEdit,
}: TokensTableProps) {
  if (tokens.length === 0) {
    return <Text c="dimmed">No tokens.</Text>;
  }

  return (
    <Table striped highlightOnHover withTableBorder>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>Name</Table.Th>
          {showOwner && <Table.Th>Owner</Table.Th>}
          <Table.Th>Created</Table.Th>
          <Table.Th>Last used</Table.Th>
          <Table.Th>Read-only</Table.Th>
          <Table.Th>Max read</Table.Th>
          <Table.Th>Status</Table.Th>
          <Table.Th aria-label="Actions" />
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {tokens.map((t) => {
          const isRevoked = !!t.revoked_at;
          return (
            <Table.Tr
              key={t.id}
              c={isRevoked ? "dimmed" : undefined}
              className={classes.row}
            >
              <Table.Td style={isRevoked ? { textDecoration: "line-through" } : undefined}>
                {t.name}
              </Table.Td>
              {showOwner && <Table.Td>{(t as ApiTokenWithOwner).owner_username}</Table.Td>}
              <Table.Td>
                <Tooltip label={formatAbsolute(t.created_at)}>
                  <span>{formatRelative(t.created_at)}</span>
                </Tooltip>
              </Table.Td>
              <Table.Td>
                {isRevoked ? (
                  <Text size="sm" c="dimmed">
                    Revoked {formatRelative(t.revoked_at)}
                  </Text>
                ) : (
                  <Tooltip label={formatAbsolute(t.last_used_at)} disabled={!t.last_used_at}>
                    <span>{formatRelative(t.last_used_at)}</span>
                  </Tooltip>
                )}
              </Table.Td>
              <Table.Td>{t.is_read_only ? <Check size={16} aria-label="read-only" /> : "—"}</Table.Td>
              <Table.Td>{formatBytes(t.max_read_bytes)}</Table.Td>
              <Table.Td>
                {isRevoked ? <Badge color="gray">Revoked</Badge> : <Badge color="green">Active</Badge>}
              </Table.Td>
              <Table.Td>
                {!isRevoked && (
                  <Group gap="xs" wrap="nowrap" className={classes.actions}>
                    {onEdit && (
                      <ActionIcon
                        variant="subtle"
                        aria-label={`Edit ${t.name}`}
                        onClick={() => onEdit(t)}
                      >
                        <Pencil size={16} />
                      </ActionIcon>
                    )}
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      aria-label={`Revoke ${t.name}`}
                      onClick={() => onRevoke(t)}
                    >
                      <Trash2 size={16} />
                    </ActionIcon>
                  </Group>
                )}
              </Table.Td>
            </Table.Tr>
          );
        })}
      </Table.Tbody>
    </Table>
  );
}
