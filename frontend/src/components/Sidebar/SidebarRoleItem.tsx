import { useState, type MouseEvent } from "react";
import { ActionIcon, NavLink, Stack, Tooltip } from "@mantine/core";
import { AlertCircle, ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { ApiError } from "@/utils/apiError";
import { RoleAvatar } from "./RoleAvatar";
import { SidebarBucketItem } from "./SidebarBucketItem";

interface SidebarRoleItemProps {
  role: string;
  collapsed: boolean;
}

export function SidebarRoleItem({ role, collapsed }: SidebarRoleItemProps) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { data: buckets, isLoading, error } = useBuckets(open ? role : undefined);

  // 403 from /api/buckets means the role's credentials cannot list all buckets
  // (R2, scoped IAM tokens). Surface as a warning icon in the sidebar so the
  // user can see *which* role has a config issue without expanding it first.
  const accessDenied = error instanceof ApiError && error.status === 403;

  const navigateToRole = () => navigate(`/r/${encodeURIComponent(role)}`);

  const toggleOpen = (e: MouseEvent) => {
    // Stop propagation so clicking the chevron doesn't also fire the parent
    // NavLink's onClick (which navigates to the role page).
    e.stopPropagation();
    setOpen((o) => !o);
  };

  if (collapsed) {
    return (
      <NavLink
        label={null}
        leftSection={<RoleAvatar role={role} />}
        onClick={navigateToRole}
        title={role}
      />
    );
  }

  return (
    <>
      <NavLink
        label={role}
        leftSection={<RoleAvatar role={role} />}
        rightSection={
          <ActionIcon
            variant="subtle"
            color="gray"
            size="sm"
            onClick={toggleOpen}
            aria-label={open ? `Collapse ${role}` : `Expand ${role}`}
          >
            <ChevronRight
              size={14}
              style={{
                transform: open ? "rotate(90deg)" : "none",
                transition: "transform 200ms ease",
              }}
            />
          </ActionIcon>
        }
        onClick={navigateToRole}
        active={accessDenied ? false : undefined}
        opened={open}
      />
      {open && (
        <Stack gap={2} pl="xs">
          {isLoading && <NavLink label="Loading…" disabled pl="lg" />}
          {accessDenied && (
            <Tooltip
              label="Cannot list buckets — open this role to fix"
              position="right"
              withArrow
            >
              <NavLink
                label="Cannot list buckets"
                leftSection={<AlertCircle size={14} />}
                color="yellow"
                onClick={navigateToRole}
                pl="lg"
              />
            </Tooltip>
          )}
          {buckets?.map((bucket) => (
            <SidebarBucketItem key={bucket} roleId={role} bucket={bucket} collapsed={false} />
          ))}
          {buckets && buckets.length === 0 && (
            <NavLink label="No buckets" disabled pl="lg" />
          )}
        </Stack>
      )}
    </>
  );
}
