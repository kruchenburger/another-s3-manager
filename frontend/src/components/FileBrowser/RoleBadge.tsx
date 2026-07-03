import { Badge } from "@mantine/core";

/** Accent role chip for the bucket page header. Uniform project accent —
 * mirrors the sidebar RoleAvatar treatment (roles are not hash-colored). */
export function RoleBadge({ roleId }: { roleId: string }) {
  return (
    <Badge
      variant="light"
      color="mutedSlateBlue"
      radius="md"
      size="lg"
      // Role names are user-defined identifiers — never uppercase them.
      style={{ textTransform: "none" }}
    >
      {roleId}
    </Badge>
  );
}
