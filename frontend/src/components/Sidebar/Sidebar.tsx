import { ActionIcon, Stack, Text } from "@mantine/core";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useMe } from "@/features/auth/hooks/useMe";
import { SidebarRoleItem } from "./SidebarRoleItem";
import classes from "./Sidebar.module.css";

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

export function Sidebar({ collapsed, onToggleCollapsed }: SidebarProps) {
  const { data: me } = useMe();
  // For non-admins, allowed_roles is on the user record. For admins in Phase 4
  // we'll merge with all roles from /api/config.
  const roles = me?.allowed_roles ?? [];

  return (
    <div className={classes.shell} data-tour="sidebar">
      <div className={classes.scrollArea}>
        {!collapsed && (
          <Text size="xs" c="dimmed" px="sm" pb="xs" tt="uppercase">
            Roles
          </Text>
        )}
        <Stack gap={2}>
          {roles.length === 0 && !collapsed && (
            <Text size="sm" c="dimmed" px="sm">
              No roles assigned. Ask your admin.
            </Text>
          )}
          {roles.map((role) => (
            <SidebarRoleItem key={role} role={role} collapsed={collapsed} />
          ))}
        </Stack>
      </div>
      <div className={classes.footer}>
        <ActionIcon
          variant="subtle"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          data-tour="collapse-btn"
        >
          {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </ActionIcon>
      </div>
    </div>
  );
}
