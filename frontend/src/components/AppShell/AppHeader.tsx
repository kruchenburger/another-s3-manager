import { ActionIcon, Burger, Group, Text, Title, Tooltip } from "@mantine/core";
import { Link, useNavigate } from "react-router-dom";
import { Github, Shield } from "lucide-react";
import { useMe } from "@/features/auth/hooks/useMe";
import { useAppInfo } from "@/hooks/useAppInfo";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";
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
  // Source app_version from /api/app-info (same hook LoginPage uses) so
  // both pre-auth and post-auth surfaces read from a single TanStack-cached
  // endpoint. /api/me also exposes app_version, but using one source means
  // a future backend rename only needs updating in one place.
  const { data: appInfo } = useAppInfo();
  const navigate = useNavigate();
  const appName = appInfo?.app_name ?? me?.app_name ?? "Another S3 Manager";
  const appVersion = appInfo?.app_version;
  const versionLabel =
    appVersion && appVersion !== "dev" ? `v${appVersion}` : null;

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
          <CubeLogo size={32} mode="static" />
          <Title order={4}>{appName}</Title>
        </Link>
        {/* Version chip lives OUTSIDE the home Link — it's static metadata,
            clicking it shouldn't navigate. */}
        {versionLabel && (
          <Text size="xs" c="dimmed">
            {versionLabel}
          </Text>
        )}
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
