import { useEffect, useState, type MouseEvent } from "react";
import { ActionIcon, NavLink, Stack, Tooltip, UnstyledButton } from "@mantine/core";
import { AlertCircle, ChevronRight } from "lucide-react";
import { useMatch, useNavigate } from "react-router-dom";
import { useBuckets } from "@/features/files/hooks/useBuckets";
import { ApiError, getErrorMessage } from "@/utils/apiError";
import { RoleAvatar } from "./RoleAvatar";
import { SidebarBucketItem } from "./SidebarBucketItem";
import classes from "./SidebarRoleItem.module.css";

interface SidebarRoleItemProps {
  role: string;
  collapsed: boolean;
}

export function SidebarRoleItem({ role, collapsed }: SidebarRoleItemProps) {
  // Auto-expand and highlight when the current URL is inside this role.
  // Pre-PR users had to click the chevron to see where they were — gave
  // no visual confirmation of the active role on landing or page reload.
  const roleMatch = useMatch(`/r/${role}/*`);
  const isActiveRole = !!roleMatch;
  const [open, setOpen] = useState(isActiveRole);
  // Keep `open` in sync when the URL changes (e.g. user switches role via
  // DefaultRolePicker → HomePage redirect → /r/RoleX). Without this effect
  // a previously-opened role would stay open and the new active role would
  // start collapsed. Only auto-OPEN on match — never auto-collapse, so a
  // manually-opened sibling stays open.
  useEffect(() => {
    if (isActiveRole) setOpen(true);
  }, [isActiveRole]);
  const navigate = useNavigate();
  const { data: buckets, isLoading, error } = useBuckets(open ? role : undefined);

  // 403 from /api/buckets means the role's credentials cannot list all buckets
  // (R2, scoped IAM tokens). Surface as a warning icon in the sidebar so the
  // user can see *which* role has a config issue without expanding it first.
  const accessDenied = error instanceof ApiError && error.status === 403;
  // Any OTHER fetch error — surface a generic warning sub-item with the
  // boundary message so the user isn't staring at a silent empty branch.
  const otherError = error && !accessDenied;

  const navigateToRole = () => navigate(`/r/${encodeURIComponent(role)}`);

  const toggleOpen = (e: MouseEvent) => {
    // Stop propagation so clicking the chevron doesn't also fire the parent
    // NavLink's onClick (which navigates to the role page).
    e.stopPropagation();
    setOpen((o) => !o);
  };

  if (collapsed) {
    // Hover hit area must match the round avatar shape; the default NavLink
    // renders a full-width rectangle around the icon which looks broken at
    // collapsed widths (~60px navbar around a ~26px circle).
    return (
      <Tooltip label={role} position="right" withArrow>
        <UnstyledButton
          onClick={navigateToRole}
          aria-label={role}
          className={classes.collapsedItem}
        >
          <RoleAvatar role={role} />
        </UnstyledButton>
      </Tooltip>
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
          {otherError && (
            <Tooltip
              label={getErrorMessage(error)}
              position="right"
              withArrow
              multiline
              w={260}
            >
              <NavLink
                label="Couldn't load buckets"
                description={getErrorMessage(error)}
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
