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
      // flexShrink 0: the chip must survive arbitrarily long bucket names
      // in the header row (the Title is the only shrinkable element there).
      style={{ textTransform: "none", flexShrink: 0 }}
    >
      {roleId}
    </Badge>
  );
}
