import { Select, Tooltip } from "@mantine/core";
import { Star } from "lucide-react";
import { useMe } from "@/features/auth/hooks/useMe";
import { useUpdateMyDefaultRole } from "@/features/auth/hooks/useUpdateMyDefaultRole";
import { runWithToasts } from "@/utils/mutationToast";

export function DefaultRolePicker() {
  const { data: me } = useMe();
  const update = useUpdateMyDefaultRole();

  // Hide the picker when there's nothing meaningful to pick — single-role and
  // no-role users would only see a degenerate dropdown.
  if (!me || me.allowed_roles.length < 2) return null;

  return (
    <Tooltip label="Default role on login" position="bottom" withArrow>
      <Select
        size="sm"
        w={180}
        value={me.default_role}
        data={me.allowed_roles}
        onChange={(value) => {
          if (value === null || value === me.default_role) return;
          runWithToasts(update, value, "Default role updated");
        }}
        aria-label="Default role"
        placeholder="No default"
        allowDeselect={false}
        leftSection={<Star size={14} />}
        comboboxProps={{ withinPortal: true }}
      />
    </Tooltip>
  );
}
