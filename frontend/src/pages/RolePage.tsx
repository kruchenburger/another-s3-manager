import { useNavigate, useParams } from "react-router-dom";
import { Button, Card, SimpleGrid, Stack, Text, Title, UnstyledButton } from "@mantine/core";
import { Database, Settings } from "lucide-react";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { ApiError, getErrorMessage } from "@/utils/apiError";

export function RolePage() {
  const params = useParams<{ roleId: string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const navigate = useNavigate();
  const { data: buckets, isLoading, error } = useBuckets(roleId);

  if (isLoading) return null;

  // 403 from /api/buckets means the role's credentials cannot list all buckets
  // (R2, MinIO scoped tokens, AWS IAM with bucket-scoped policies). The backend
  // returns a friendly message; we surface it with a CTA back to the admin form
  // so the user can fill in "Allowed Buckets" without leaving the v2 SPA flow.
  if (error instanceof ApiError && error.status === 403) {
    return (
      <EmptyState
        tone="warning"
        title="Cannot list buckets for this role"
        description={getErrorMessage(error)}
        cta={
          <Button
            component="a"
            href="/admin"
            leftSection={<Settings size={16} />}
            variant="filled"
            color="amber"
          >
            Open admin to fix
          </Button>
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

  return (
    <Stack gap="md">
      <Title order={2}>{roleId}</Title>
      <Text c="dimmed">Pick a bucket to browse files.</Text>
      <SimpleGrid cols={{ base: 1, sm: 2, md: 3, lg: 4 }} spacing="md">
        {buckets.map((bucket) => (
          <UnstyledButton
            key={bucket}
            onClick={() => navigate(`/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`)}
            aria-label={`Open bucket ${bucket}`}
          >
            <Card withBorder shadow="sm" padding="lg">
              <Stack align="center" gap="sm">
                <Database size={48} color="var(--mantine-color-amber-6)" />
                <Text fw={600}>{bucket}</Text>
              </Stack>
            </Card>
          </UnstyledButton>
        ))}
      </SimpleGrid>
    </Stack>
  );
}
