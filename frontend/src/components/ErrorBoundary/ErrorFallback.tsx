import { useRef } from "react";
import { Button, Container, Stack, Text, Title, UnstyledButton } from "@mantine/core";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";

interface ErrorFallbackProps {
  error: Error;
  onReset: () => void;
}

export function ErrorFallback({ error, onReset }: ErrorFallbackProps) {
  // crash mode supports replay — clicking the burger re-runs the scatter animation
  const replayRef = useRef<(() => void) | null>(null);

  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <UnstyledButton
          onClick={() => replayRef.current?.()}
          aria-label="Replay crash animation"
          title="Click to crash again"
        >
          <BurgerLogo size={128} mode="crash" onReplayRef={replayRef} />
        </UnstyledButton>
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
