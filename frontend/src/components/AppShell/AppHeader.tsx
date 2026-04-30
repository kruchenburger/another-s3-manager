import { Group, Title } from "@mantine/core";
import { useMe } from "@/features/auth/hooks/useMe";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { ThemeToggle } from "@/components/AppShell/ThemeToggle";
import { UserMenu } from "@/components/AppShell/UserMenu";

export function AppHeader() {
  const { data: me } = useMe();
  const appName = me?.app_name ?? "Another S3 Manager";

  return (
    <Group h="100%" px="md" justify="space-between">
      <Group gap="sm">
        <BurgerLogo size={32} />
        <Title order={4}>{appName}</Title>
      </Group>
      <Group gap="sm">
        <ThemeToggle />
        <UserMenu />
      </Group>
    </Group>
  );
}
