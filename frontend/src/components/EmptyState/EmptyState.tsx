import type { ReactNode } from "react";
import { Container, Stack, Text, Title } from "@mantine/core";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";

/**
 * Visual tone for the empty state. Kept as an external prop for API stability
 * even though CubeLogo is now rendered static regardless of tone — every
 * EmptyState surface (403 forbidden, empty folder, missing role) prefers the
 * static logo so the user's attention stays on the title/CTA, not the icon.
 */
export type EmptyStateTone = "neutral" | "warning";

interface EmptyStateProps {
  title: string;
  description?: string;
  cta?: ReactNode;
  burgerSize?: number;
  tone?: EmptyStateTone;
}

export function EmptyState({
  title,
  description,
  cta,
  burgerSize = 64,
}: EmptyStateProps) {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <CubeLogo size={burgerSize} mode="static" />
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
