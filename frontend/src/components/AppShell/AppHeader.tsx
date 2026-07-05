import { ActionIcon, Box, Burger, Group, Text, Title, Tooltip } from "@mantine/core";
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
          {/* Full name is too wide for a phone header row (it pushed the
              theme toggle + avatar out of the fixed 60px header, painting
              them over the page). Below sm the brand collapses to the short
              mark "as3m" (same as the token prefix). */}
          <Title order={4} visibleFrom="sm">
            {appName}
          </Title>
          <Title order={4} hiddenFrom="sm">
            as3m
          </Title>
        </Link>
        {/* Version chip lives OUTSIDE the home Link — it's static metadata,
            clicking it shouldn't navigate. Hidden on phones (width budget). */}
        {versionLabel && (
          <Text size="xs" c="dimmed" visibleFrom="sm">
            {versionLabel}
          </Text>
        )}
      </Group>
      {/* Mobile (<sm): the AppShell header is a fixed 60px — a wrapped second
          row of controls paints OVER the page content. Hide the secondary
          controls: Admin Console stays reachable via UserMenu, GitHub is
          non-essential, the default-role picker lives in the burger sidebar
          flow. Theme toggle + user menu always fit. */}
      <Group gap="sm">
        {me?.is_admin && (
          <Tooltip label="Admin Console">
            {/* Airify: header icons are borderless at rest (mockup) — subtle
                shows a quiet wash only on hover; keyboard focus keeps the
                global focus-visible ring. */}
            <ActionIcon
              visibleFrom="sm"
              variant="subtle"
              color="gray"
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
            visibleFrom="sm"
            component="a"
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            variant="subtle"
            color="gray"
            size="lg"
            aria-label="View source on GitHub"
          >
            <Github size={18} />
          </ActionIcon>
        </Tooltip>
        <Box visibleFrom="sm">
          <DefaultRolePicker />
        </Box>
        <ThemeToggle />
        <UserMenu />
      </Group>
    </Group>
  );
}
