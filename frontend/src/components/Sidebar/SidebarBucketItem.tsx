import { NavLink } from "@mantine/core";
import { Database } from "lucide-react";
import { useNavigate, useMatch } from "react-router-dom";

interface SidebarBucketItemProps {
  roleId: string;
  bucket: string;
  collapsed: boolean;
}

export function SidebarBucketItem({ roleId, bucket, collapsed }: SidebarBucketItemProps) {
  const navigate = useNavigate();
  const match = useMatch(`/r/${roleId}/b/${bucket}/*`);
  const active = !!match;

  return (
    <NavLink
      label={collapsed ? null : bucket}
      leftSection={<Database size={14} />}
      active={active}
      onClick={() => navigate(`/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`)}
      title={collapsed ? bucket : undefined}
      pl={collapsed ? "xs" : "lg"}
    />
  );
}
