import { Modal } from "@mantine/core";
import { CreateTokenFormFields, type CreateTokenFormFieldsProps } from "./CreateTokenFormFields";

interface CreateTokenModalProps extends Omit<CreateTokenFormFieldsProps, "onClose"> {
  opened: boolean;
  onClose: () => void;
}

/**
 * Modal wrapper for the create-token form. Kept around for one
 * specific call-site: `UserTokensList` inside the admin `UserDrawer`.
 * When the admin opens the user-edit drawer and clicks "Create
 * token" on the embedded token list, we surface the form in a
 * centred modal — Drawer-on-Drawer reads as visual clutter and
 * Mantine's focus-trap struggles with the overlap.
 *
 * Standalone token pages (AdminApiTokensPage, ApiTokensPage) use
 * `CreateTokenDrawer` instead so the create affordance matches the
 * right-side Drawer pattern used by every other admin list page.
 */
export function CreateTokenModal({
  opened,
  onClose,
  onSubmit,
  loading,
  used,
  limit,
  adminMode,
  availableUsers,
}: CreateTokenModalProps) {
  return (
    <Modal opened={opened} onClose={onClose} title="Create MCP token" centered size="md" radius="lg">
      <CreateTokenFormFields
        onClose={onClose}
        onSubmit={onSubmit}
        loading={loading}
        used={used}
        limit={limit}
        adminMode={adminMode}
        availableUsers={availableUsers}
      />
    </Modal>
  );
}
