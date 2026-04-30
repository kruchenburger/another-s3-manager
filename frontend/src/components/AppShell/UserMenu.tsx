import { Avatar, Menu, Text, UnstyledButton, Group } from "@mantine/core";
import { IconLogout, IconUser } from "@tabler/icons-react";
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
      onSettled: () => navigate("/login", { replace: true }),
    });
  };

  return (
    <Menu position="bottom-end" withArrow>
      <Menu.Target>
        <UnstyledButton aria-label="User menu">
          <Group gap="xs">
            <Avatar color="cheese" radius="xl" size="sm">
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
        <Menu.Item leftSection={<IconUser size={14} />} disabled>
          {me.is_admin ? "Administrator" : "User"}
        </Menu.Item>
        <Menu.Divider />
        <Menu.Item color="red" leftSection={<IconLogout size={14} />} onClick={handleLogout}>
          Logout
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
