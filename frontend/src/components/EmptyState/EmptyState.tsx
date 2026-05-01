import type { ReactNode } from "react";
import { Container, Stack, Text, Title } from "@mantine/core";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";

interface EmptyStateProps {
  title: string;
  description?: string;
  cta?: ReactNode;
  burgerSize?: number;
}

export function EmptyState({ title, description, cta, burgerSize = 64 }: EmptyStateProps) {
  return (
    <Container size="sm" py="xl">
      <Stack align="center" gap="md">
        <BurgerLogo size={burgerSize} mode="idle" />
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
