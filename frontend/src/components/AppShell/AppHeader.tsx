import { ActionIcon, Burger, Group, Title, Tooltip } from "@mantine/core";
import { Link, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { useMe } from "@/features/auth/hooks/useMe";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { ThemeToggle } from "@/components/AppShell/ThemeToggle";
import { UserMenu } from "@/components/AppShell/UserMenu";

interface AppHeaderProps {
  navOpened: boolean;
  onNavToggle: () => void;
}

export function AppHeader({ navOpened, onNavToggle }: AppHeaderProps) {
  const { data: me } = useMe();
  const navigate = useNavigate();
  const appName = me?.app_name ?? "Another S3 Manager";

  return (
    <Group h="100%" px="md" justify="space-between">
      <Group gap="sm">
        <Burger opened={navOpened} onClick={onNavToggle} hiddenFrom="sm" size="sm" />
        <Link
          to="/"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            textDecoration: "none",
            color: "inherit",
            cursor: "pointer",
          }}
          aria-label="Go to home"
        >
          <BurgerLogo size={32} mode="static" />
          <Title order={4}>{appName}</Title>
        </Link>
      </Group>
      <Group gap="sm">
        {me?.is_admin && (
          <Tooltip label="Admin Console">
            <ActionIcon
              variant="default"
              size="lg"
              onClick={() => navigate("/admin/users")}
              aria-label="Open admin console"
            >
              <Shield size={18} />
            </ActionIcon>
          </Tooltip>
        )}
        <ThemeToggle />
        <UserMenu />
      </Group>
    </Group>
  );
}
