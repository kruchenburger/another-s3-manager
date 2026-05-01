import { Burger, Group, Title } from "@mantine/core";
import { useMe } from "@/features/auth/hooks/useMe";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { ThemeToggle } from "@/components/AppShell/ThemeToggle";
import { UserMenu } from "@/components/AppShell/UserMenu";
import { HelpButton } from "@/components/AppShell/HelpButton";

interface AppHeaderProps {
  navOpened: boolean;
  onNavToggle: () => void;
  onOpenTour: () => void;
}

export function AppHeader({ navOpened, onNavToggle, onOpenTour }: AppHeaderProps) {
  const { data: me } = useMe();
  const appName = me?.app_name ?? "Another S3 Manager";

  return (
    <Group h="100%" px="md" justify="space-between">
      <Group gap="sm">
        <Burger opened={navOpened} onClick={onNavToggle} hiddenFrom="sm" size="sm" />
        <BurgerLogo size={32} mode="static" />
        <Title order={4}>{appName}</Title>
      </Group>
      <Group gap="sm">
        <HelpButton onClick={onOpenTour} />
        <ThemeToggle />
        <UserMenu />
      </Group>
    </Group>
  );
}
