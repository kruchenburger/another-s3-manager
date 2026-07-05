import { Modal } from "@mantine/core";

import {
  TokenEditFormFields,
  type TokenEditFormFieldsProps,
} from "./TokenEditFormFields";

interface TokenEditModalProps
  extends Omit<TokenEditFormFieldsProps, "variant"> {
  opened: boolean;
}

/**
 * Modal wrapper around `TokenEditFormFields`. Used inside the admin UserDrawer
 * where stacking another right-Drawer would: (a) overlap the parent drawer
 * fully so the user loses parent context, (b) fight the Mantine focus-trap
 * stack so closing the inner drawer can also close the outer one. A modal
 * sits in its own overlay layer and dismisses cleanly without disturbing the
 * underlying drawer.
 *
 * For standalone token pages (no parent drawer) use `TokenEditDrawer` instead
 * — it follows the right-Drawer pattern shared by every other admin entity
 * edit screen.
 */
export function TokenEditModal({
  opened,
  token,
  loading,
  onClose,
  onSubmit,
}: TokenEditModalProps) {
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Edit MCP token"
      centered
      radius="lg"
    >
      <TokenEditFormFields
        token={token}
        loading={loading}
        onClose={onClose}
        onSubmit={onSubmit}
        variant="modal"
      />
    </Modal>
  );
}
