import { Drawer } from "@mantine/core";

import {
  TokenEditFormFields,
  type TokenEditFormFieldsProps,
} from "./TokenEditFormFields";

interface TokenEditDrawerProps
  extends Omit<TokenEditFormFieldsProps, "variant"> {
  opened: boolean;
}

/**
 * Drawer wrapper around `TokenEditFormFields`. Used on standalone token pages
 * (`/v2/api-tokens`, `/v2/admin/api-tokens`) for consistency with the other
 * admin entity edit drawers (UserDrawer, RoleDrawer).
 *
 * NOT used inside the admin UserDrawer — see `TokenEditModal` for that path
 * (a side-drawer over a side-drawer fights the focus stack and the second
 * overlay swallows the parent drawer).
 */
export function TokenEditDrawer({
  opened,
  token,
  loading,
  onClose,
  onSubmit,
}: TokenEditDrawerProps) {
  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="md"
      title="Edit MCP token"
      styles={{
        body: {
          display: "flex",
          flexDirection: "column",
          height: "calc(100% - 60px)",
          overflow: "hidden",
        },
      }}
    >
      <TokenEditFormFields
        token={token}
        loading={loading}
        onClose={onClose}
        onSubmit={onSubmit}
        variant="drawer"
      />
    </Drawer>
  );
}
