import type { ReactNode } from "react";
import { Container, Stack, Text, Title } from "@mantine/core";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";

type EmptyStateTone = "neutral" | "warning";

interface EmptyStateProps {
  title: string;
  description?: string;
  cta?: ReactNode;
  burgerSize?: number;
  /**
   * Visual tone for the empty state.
   * - "neutral" (default): idle BurgerLogo, dimmed description text.
   * - "warning": error-mode BurgerLogo for "we hit a wall" states (403, misconfig)
   *   that still need a hopeful CTA, not a hard ErrorPage.
   */
  tone?: EmptyStateTone;
}

export function EmptyState({
  title,
  description,
  cta,
  burgerSize = 64,
  tone = "neutral",
}: EmptyStateProps) {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <BurgerLogo size={burgerSize} mode={tone === "warning" ? "error" : "idle"} />
        <Title order={3}>{title}</Title>
        {description && (
          <Text c="dimmed" ta="center">
            {description}
          </Text>
        )}
        {cta}
      </Stack>
    </Container>
  );
}
