import { Avatar } from "@mantine/core";

interface RoleAvatarProps {
  role: string;
  size?: number | "sm" | "md" | "lg";
}

export function RoleAvatar({ role, size = "sm" }: RoleAvatarProps) {
  const initial = role.charAt(0).toUpperCase();
  return (
    <Avatar color="mutedSlateBlue" radius="xl" size={size} aria-label={role}>
      {initial}
    </Avatar>
  );
}
