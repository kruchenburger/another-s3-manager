import { useState } from "react";
import {
  Button,
  Container,
  Stack,
  Text,
  Title,
  UnstyledButton,
} from "@mantine/core";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";

interface ErrorFallbackProps {
  error: Error;
  onReset: () => void;
}

export function ErrorFallback({ error, onReset }: ErrorFallbackProps) {
  // Crash mode supports replay — clicking the logo bumps a key so the
  // CubeLogo unmounts/remounts and the GSAP timeline rebuilds from scratch.
  // (The old API used an `onReplayRef` callback; CubeLogo dropped that prop
  // and relies on remount via key for replay.)
  const [replayKey, setReplayKey] = useState(0);

  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <UnstyledButton
          onClick={() => setReplayKey((k) => k + 1)}
          aria-label="Replay crash animation"
          title="Click to crash again"
        >
          <CubeLogo key={replayKey} size={128} mode="crash" />
        </UnstyledButton>
        <Title order={2}>Something went wrong</Title>
        <Text c="dimmed" ta="center">
          The app hit an unexpected error. Try reloading; if it persists,
          contact your administrator.
        </Text>
        <Text size="sm" c="red" ff="monospace" ta="center">
          {error.message}
        </Text>
        <Button onClick={onReset}>Reload</Button>
      </Stack>
    </Container>
  );
}
