import { Drawer } from "@mantine/core";
import { CreateTokenFormFields, type CreateTokenFormFieldsProps } from "./CreateTokenFormFields";

interface CreateTokenDrawerProps extends Omit<CreateTokenFormFieldsProps, "onClose"> {
  opened: boolean;
  onClose: () => void;
}

/**
 * Drawer wrapper for the create-token form. Used on standalone token
 * pages — `AdminApiTokensPage` and `ApiTokensPage` — so the create
 * affordance matches the right-side Drawer pattern used by
 * BansPage/RolesPage/UsersPage edit flows.
 *
 * NOT used inside the admin UserDrawer (UserTokensList.tsx) — a
 * Drawer-stacked-on-Drawer reads awkwardly visually and Mantine's
 * focus-trap struggles with the overlap. That call-site keeps
 * CreateTokenModal which sits cleanly above the open UserDrawer.
 */
export function CreateTokenDrawer({
  opened,
  onClose,
  onSubmit,
  loading,
  used,
  limit,
  adminMode,
  availableUsers,
}: CreateTokenDrawerProps) {
  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      title="Create MCP token"
      position="right"
      size="md"
      radius="md"
    >
      <CreateTokenFormFields
        onClose={onClose}
        onSubmit={onSubmit}
        loading={loading}
        used={used}
        limit={limit}
        adminMode={adminMode}
        availableUsers={availableUsers}
      />
    </Drawer>
  );
}
