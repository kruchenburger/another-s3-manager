import { NavLink, Stack, Text } from "@mantine/core";
import { ArrowLeft, Ban, Drama, Key, Settings, Users } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";

interface NavItem {
  label: string;
  to: string;
  icon: React.ReactNode;
}

const accountsItems: NavItem[] = [
  { label: "Users", to: "/admin/users", icon: <Users size={16} /> },
  { label: "Bans", to: "/admin/bans", icon: <Ban size={16} /> },
  { label: "MCP Tokens", to: "/admin/api-tokens", icon: <Key size={16} /> },
];

const infrastructureItems: NavItem[] = [
  { label: "Roles", to: "/admin/roles", icon: <Drama size={16} /> },
  { label: "Settings", to: "/admin/settings", icon: <Settings size={16} /> },
];

function SectionHeader({ children }: { children: string }) {
  return (
    <Text size="xs" c="dimmed" tt="uppercase" fw={600} mt="md" mb={4} px="sm">
      {children}
    </Text>
  );
}

export function AdminSidebar() {
  const location = useLocation();
  const navigate = useNavigate();

  const renderItem = (item: NavItem) => (
    <NavLink
      key={item.to}
      label={item.label}
      leftSection={item.icon}
      active={location.pathname.startsWith(item.to)}
      onClick={() => navigate(item.to)}
    />
  );

  return (
    <Stack gap={2} h="100%">
      <SectionHeader>Accounts</SectionHeader>
      {accountsItems.map(renderItem)}
      <SectionHeader>Infrastructure</SectionHeader>
      {infrastructureItems.map(renderItem)}
      <Stack flex={1} />
      <NavLink
        label="Back to files"
        leftSection={<ArrowLeft size={16} />}
        onClick={() => navigate("/")}
        mt="md"
      />
    </Stack>
  );
}
