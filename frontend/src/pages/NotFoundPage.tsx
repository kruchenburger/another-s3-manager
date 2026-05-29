import { Button, Container, Stack, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";

export function NotFoundPage() {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <CubeLogo size={128} mode="notfound" />
        <Title order={2}>Page not found</Title>
        <Text c="dimmed">
          The page you were looking for doesn't exist (or moved).
        </Text>
        <Button component={Link} to="/">
          Back to home
        </Button>
      </Stack>
    </Container>
  );
}
