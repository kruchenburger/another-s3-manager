import { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button, Group, Stack, Table, Text, Title } from "@mantine/core";
import { Database, Settings } from "lucide-react";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { useMe } from "@/features/auth/hooks/useMe";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { QueryErrorState } from "@/components/QueryErrorState/QueryErrorState";
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

  // 403 from /api/buckets comes from TWO distinct sources — each needs its own
  // copy. The previous version conflated both, so a user who simply wasn't
  // granted the role saw a misleading "ask your admin to configure Allowed
  // Buckets" hint that had nothing to do with the real cause.
  //
  //   A. ROLE-LEVEL DENY — `validate_role_access` rejected the user because
  //      the role isn't in their `allowed_roles`. Backend message starts with
  //      "Access denied: You don't have permission to use role 'X'".
  //      Fix: admin must grant the role to the user; allowed_buckets is
  //      irrelevant.
  //
  //   B. S3-CREDENTIALS-LEVEL DENY — the role's credentials cannot
  //      `s3:ListAllMyBuckets` (R2, MinIO scoped tokens, AWS IAM with
  //      bucket-scoped policies). Backend message is the longer
  //      "Your credentials don't have permission to list all buckets...".
  //      Fix: admin must populate `allowed_buckets` on the role.
  //
  // Discriminator: substring match against the backend message. This is
  // pragmatic (rather than relying on a typed error code) because the
  // route still emits both messages as plain strings — see
  // src/another_s3_manager/main.py around the list_buckets handler.
  if (error instanceof ApiError && error.status === 403) {
    const isAdmin = me?.is_admin === true;
    const message = getErrorMessage(error);
    const isRoleLevel =
      message.includes("don't have permission to use role") ||
      message.startsWith("Access denied:");

    if (isRoleLevel) {
      const adminRoleHint =
        "Edit this user's profile and add this role to their allowed roles.";
      const userRoleHint =
        "Ask your administrator to grant you access to this role.";
      return (
        <EmptyState
          tone="warning"
          title="Role not available"
          description={`${message} ${isAdmin ? adminRoleHint : userRoleHint}`}
          cta={
            isAdmin ? (
              <Button
                component="a"
                href="/admin"
                leftSection={<Settings size={16} />}
                variant="filled"
              >
                Open admin to fix
              </Button>
            ) : undefined
          }
        />
      );
    }

    const adminBucketHint =
      "Edit this role and fill in 'Allowed Buckets' with the bucket names you want to access.";
    const userBucketHint =
      "Ask your administrator to configure 'Allowed Buckets' on this role.";
    return (
      <EmptyState
        tone="warning"
        title="Cannot list buckets for this role"
        description={`${message} ${isAdmin ? adminBucketHint : userBucketHint}`}
        cta={
          isAdmin ? (
            <Button
              component="a"
              href="/admin"
              leftSection={<Settings size={16} />}
              variant="filled"
            >
              Open admin to fix
            </Button>
          ) : undefined
        }
      />
    );
  }

  // Non-403 errors (500, network failure, anything else) — surface the boundary
  // message instead of falling through to the empty-buckets EmptyState which
  // would mislead the user into thinking the role is misconfigured. The 403
  // case above keeps its bespoke admin/non-admin CTA copy.
  if (error) {
    return <QueryErrorState error={error} title="Couldn't load buckets" />;
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
                navigate(
                  `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`,
                )
              }
              style={{ cursor: "pointer" }}
              aria-label={`Open bucket ${bucket}`}
            >
              <Table.Td>
                <Group gap="sm" wrap="nowrap">
                  <Database
                    size={18}
                    color="var(--mantine-primary-color-filled)"
                  />
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
