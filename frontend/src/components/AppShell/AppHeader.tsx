import { ActionIcon, Burger, Group, Text, Title, Tooltip } from "@mantine/core";
import { Link, useNavigate } from "react-router-dom";
import { Github, Shield } from "lucide-react";
import { useMe } from "@/features/auth/hooks/useMe";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { ThemeToggle } from "@/components/AppShell/ThemeToggle";
import { UserMenu } from "@/components/AppShell/UserMenu";
import { DefaultRolePicker } from "@/components/AppShell/DefaultRolePicker";
import { GITHUB_URL } from "@/constants/links";

interface AppHeaderProps {
  navOpened: boolean;
  onNavToggle: () => void;
}

export function AppHeader({ navOpened, onNavToggle }: AppHeaderProps) {
  const { data: me } = useMe();
  const navigate = useNavigate();
  const appName = me?.app_name ?? "Another S3 Manager";
  const versionLabel =
    me?.app_version && me.app_version !== "dev" ? `v${me.app_version}` : null;

  return (
    <Group h="100%" px="md" justify="space-between">
      <Group gap="sm">
        <Burger
          opened={navOpened}
          onClick={onNavToggle}
          hiddenFrom="sm"
          size="sm"
        />
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
          {versionLabel && (
            <Text size="xs" c="dimmed" component="span">
              {versionLabel}
            </Text>
          )}
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
        <Tooltip label="View source on GitHub">
          <ActionIcon
            component="a"
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            variant="default"
            size="lg"
            aria-label="View source on GitHub"
          >
            <Github size={18} />
          </ActionIcon>
        </Tooltip>
        <DefaultRolePicker />
        <ThemeToggle />
        <UserMenu />
      </Group>
    </Group>
  );
}
