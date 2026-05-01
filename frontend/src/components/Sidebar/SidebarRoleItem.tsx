import { useState } from "react";
import { NavLink, Stack } from "@mantine/core";
import { ChevronRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { RoleAvatar } from "./RoleAvatar";
import { SidebarBucketItem } from "./SidebarBucketItem";

interface SidebarRoleItemProps {
  role: string;
  collapsed: boolean;
}

export function SidebarRoleItem({ role, collapsed }: SidebarRoleItemProps) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { data: buckets, isLoading } = useBuckets(open ? role : undefined);

  const handleClick = () => {
    if (collapsed) {
      // Collapsed mode: click avatar navigates to role page (bucket grid)
      navigate(`/r/${encodeURIComponent(role)}`);
      return;
    }
    setOpen((o) => !o);
  };

  if (collapsed) {
    return (
      <NavLink
        label={null}
        leftSection={<RoleAvatar role={role} />}
        onClick={handleClick}
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
          <ChevronRight
            size={14}
            style={{
              transform: open ? "rotate(90deg)" : "none",
              transition: "transform 200ms ease",
            }}
          />
        }
        onClick={handleClick}
        opened={open}
      />
      {open && (
        <Stack gap={2} pl="xs">
          {isLoading && <NavLink label="Loading…" disabled pl="lg" />}
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
