import { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button, Group, Stack, Table, Text, Title } from "@mantine/core";
import { Database, Settings } from "lucide-react";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { useMe } from "@/features/auth/hooks/useMe";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { ApiError, getErrorMessage } from "@/utils/apiError";

export function RolePage() {
  const params = useParams<{ roleId: string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const navigate = useNavigate();
  const { data: buckets, isLoading, error } = useBuckets(roleId);
  const { data: me } = useMe();

  // Auto-open the bucket when the role has exactly one allowed bucket — saves
  // a click on the otherwise-degenerate "pick a bucket" list. `replace: true`
  // keeps Back returning to home instead of bouncing through this page.
  // Hook is declared before any early return to keep React's hook order stable.
  // The `!error` guard avoids redirecting into an unreachable bucket when the
  // hook returns stale cached buckets (length 1) while a fresh fetch is failing
  // with 403 — the user should see the 403 EmptyState instead of being silently
  // bounced past it.
  useEffect(() => {
    if (!error && buckets && buckets.length === 1) {
      navigate(
        `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(buckets[0]!)}`,
        { replace: true },
      );
    }
  }, [buckets, roleId, navigate, error]);

  if (isLoading) return null;

  // 403 from /api/buckets means the role's credentials cannot list all buckets
  // (R2, MinIO scoped tokens, AWS IAM with bucket-scoped policies). Backend
  // returns a generic explanation; we layer a role-appropriate CTA on top:
  // admins get a button to the admin UI, non-admins get a "ask your admin" hint
  // (no CTA — they have no access to /admin).
  if (error instanceof ApiError && error.status === 403) {
    const isAdmin = me?.is_admin === true;
    const adminHint = "Edit this role and fill in 'Allowed Buckets' with the bucket names you want to access.";
    const userHint = "Ask your administrator to configure 'Allowed Buckets' on this role.";
    return (
      <EmptyState
        tone="warning"
        title="Cannot list buckets for this role"
        description={`${getErrorMessage(error)} ${isAdmin ? adminHint : userHint}`}
        cta={
          isAdmin ? (
            <Button
              component="a"
              href="/admin"
              leftSection={<Settings size={16} />}
              variant="filled"
              color="amber"
            >
              Open admin to fix
            </Button>
          ) : undefined
        }
      />
    );
  }

  if (!buckets || buckets.length === 0) {
    return (
      <EmptyState
        title="No buckets accessible"
        description={`Role "${roleId}" has no buckets configured. Contact your admin.`}
      />
    );
  }

  // Single-bucket roles auto-redirect via the effect above; render nothing in
  // the same tick so the table doesn't flash before navigation. The `!error`
  // mirror of the effect guard prevents a blank screen when stale single-bucket
  // data coexists with a fresh non-403 error — without it the effect would
  // skip the redirect but this branch would still hide the EmptyState.
  if (!error && buckets.length === 1) return null;

  return (
    <Stack gap="md">
      <Title order={2}>{roleId}</Title>
      <Text c="dimmed">Pick a bucket to browse files.</Text>
      <Table highlightOnHover striped="even" verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Bucket</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {buckets.map((bucket) => (
            <Table.Tr
              key={bucket}
              onClick={() =>
                navigate(`/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`)
              }
              style={{ cursor: "pointer" }}
              aria-label={`Open bucket ${bucket}`}
            >
              <Table.Td>
                <Group gap="sm" wrap="nowrap">
                  <Database size={18} color="var(--mantine-color-amber-6)" />
                  <Text>{bucket}</Text>
                </Group>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Stack>
  );
}
