import { useNavigate, useParams } from "react-router-dom";
import { Card, SimpleGrid, Stack, Text, Title, UnstyledButton } from "@mantine/core";
import { Database } from "lucide-react";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { EmptyState } from "@/components/EmptyState/EmptyState";

export function RolePage() {
  const params = useParams<{ roleId: string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const navigate = useNavigate();
  const { data: buckets, isLoading } = useBuckets(roleId);

  if (isLoading) return null;

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
