import { Button, Container, Stack, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";

/**
 * 403 Forbidden — the user is authenticated but lacks privileges for this route.
 * Used by AdminGuard (Phase 4) when a non-admin hits `/v2/admin/*`.
 */
export function ForbiddenPage() {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <CubeLogo size={128} mode="error" />
        <Title order={2}>Forbidden</Title>
        <Text c="dimmed" ta="center">
          You don't have permission to view this page. If you think this is a
          mistake, contact your administrator.
        </Text>
        <Button component={Link} to="/">
          Back to home
        </Button>
      </Stack>
    </Container>
  );
}
