import { Button, Container, Stack, Text, Title } from "@mantine/core";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";

interface ErrorFallbackProps {
  error: Error;
  onReset: () => void;
}

export function ErrorFallback({ error, onReset }: ErrorFallbackProps) {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <BurgerLogo size={64} />
        <Title order={2}>Something went wrong</Title>
        <Text c="dimmed" ta="center">
          The app hit an unexpected error. Try reloading; if it persists, contact your administrator.
        </Text>
        <Text size="sm" c="red" ff="monospace" ta="center">
          {error.message}
        </Text>
        <Button onClick={onReset}>Reload</Button>
      </Stack>
    </Container>
  );
}
