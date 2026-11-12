import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, renderHook } from "@testing-library/react";
import { useRolePermissions } from "@/features/auth/hooks/useRolePermissions";
import { useMe } from "@/features/auth/hooks/useMe";

vi.mock("@/features/auth/hooks/useMe", () => ({ useMe: vi.fn() }));
afterEach(cleanup);

describe("useRolePermissions", () => {
  it.each([
    [undefined, false, null],
    [{ disable_deletion: false, role_permissions: {} }, false, null],
    [
      { disable_deletion: false, role_permissions: { r: { delete: true } } },
      true,
      null,
    ],
    [
      { disable_deletion: false, role_permissions: { r: { delete: false } } },
      false,
      "Deleting is turned off for role r",
    ],
    [
      { disable_deletion: true, role_permissions: { r: { delete: false } } },
      false,
      "Deletion is disabled in the server config.",
    ],
  ])("derives permission from %j", (data, canDelete, reason) => {
    vi.mocked(useMe).mockReturnValue({ data } as never);
    const { result } = renderHook(() => useRolePermissions("r"));
    expect(result.current).toEqual({ canDelete, reason });
  });

  it("fails closed on an error even when stale data permits deletion", () => {
    vi.mocked(useMe).mockReturnValue({
      data: { role_permissions: { r: { delete: true } } },
      isError: true,
    } as never);
    expect(
      renderHook(() => useRolePermissions("r")).result.current.canDelete,
    ).toBe(false);
  });
});
