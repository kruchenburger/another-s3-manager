import { Avatar, Menu, Text, UnstyledButton, Group } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { Key, KeyRound, LogOut, Shield } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { useLogout } from "@/features/auth/hooks/useLogout";

export function UserMenu() {
  const { data: me } = useMe();
  const logout = useLogout();
  const navigate = useNavigate();

  if (!me) return null;

  const initial = me.username.charAt(0).toUpperCase();

  const handleLogout = (): void => {
    logout.mutate(undefined, {
      onSuccess: () => navigate("/login", { replace: true }),
      onError: () =>
        notifications.show({
          color: "red",
          title: "Couldn't sign out",
          message:
            "Please close the tab manually — your session may still be active on the server.",
          autoClose: false,
        }),
    });
  };

  return (
    <Menu position="bottom-end" withArrow>
      <Menu.Target>
        <UnstyledButton aria-label="User menu">
          <Group gap="xs">
            <Avatar color="mutedSlateBlue" radius="xl" size="sm">
              {initial}
            </Avatar>
            <Text size="sm" fw={500} visibleFrom="sm">
              {me.username}
            </Text>
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Signed in as {me.username}</Menu.Label>
        <Menu.Item
          leftSection={<KeyRound size={14} />}
          onClick={() => navigate("/change-password")}
        >
          Change password
        </Menu.Item>
        <Menu.Item
          leftSection={<Key size={14} />}
          onClick={() => navigate("/api-tokens")}
        >
          MCP tokens
        </Menu.Item>
        {me.is_admin && (
          <Menu.Item
            leftSection={<Shield size={14} />}
            onClick={() => navigate("/admin/users")}
          >
            Admin Console
          </Menu.Item>
        )}
        <Menu.Divider />
        <Menu.Item
          color="red"
          leftSection={<LogOut size={14} />}
          onClick={handleLogout}
        >
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
