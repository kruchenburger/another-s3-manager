import { Card, Stack, Text, Title } from "@mantine/core";
import { useMe } from "@/features/auth/hooks/useMe";

export function HomePage() {
  const { data: me } = useMe();

  return (
    <Stack gap="md">
      <Title order={2}>Welcome, {me?.username ?? "user"}</Title>
      <Card>
        <Text c="dimmed">
          The new React UI is up and running. Bucket browser, file upload, and admin tools land in Phase 3.
        </Text>
      </Card>
    </Stack>
  );
}
