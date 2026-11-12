import { useMe } from "./useMe";
import {
  DELETION_DISABLED,
  ROLE_DELETION_DISABLED,
} from "@/features/files/utils/folderOperations";

export function useRolePermissions(role: string) {
  const me = useMe();
  if (!me.data || me.isPending || me.isError)
    return { canDelete: false, reason: null };
  if (me.data.disable_deletion)
    return { canDelete: false, reason: DELETION_DISABLED };
  const permission = me.data.role_permissions?.[role];
  return {
    canDelete: permission?.delete === true,
    reason:
      permission?.delete === false
        ? ROLE_DELETION_DISABLED.replace("<r>", role)
        : null,
  };
}
